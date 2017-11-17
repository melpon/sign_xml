defmodule SignXML.Verifier do
  defp find_all(node, xpath) do
    node = Libxml.Node.extract(node)
    Libxml.XPath.safe_new_context(node.doc, fn ctx ->
      ctx = Libxml.XPath.Context.extract(ctx)
      ctx = %{ctx | node: node}
      Libxml.XPath.Context.apply(ctx)
      Libxml.XPath.safe_eval(ctx, xpath, fn obj ->
        obj = Libxml.XPath.Object.extract(obj)
        case obj.type do
          :nodeset ->
            if obj.content == nil do
              {:nodeset, []}
            else
              {:nodeset, Libxml.XPath.NodeSet.extract(obj.content).nodes}
            end
          :boolean -> {:boolean, obj.content}
          :number -> {:number, obj.content}
          :string -> {:string, Libxml.Char.extract(obj.content).content}
        end
      end)
    end)
  end

  defp find_all_node(node, xpath) do
    {:nodeset, nodes} = find_all(node, xpath)
    nodes
  end
  defp find_single_or_zero_node(node, xpath) do
    nodes = find_all_node(node, xpath)
    case length(nodes) do
      0 -> nil
      1 -> Enum.fetch!(nodes, 0)
      _ -> raise "not single or zero node #{length(nodes)}"
    end
  end
  defp find_single_node(node, xpath) do
    nodes = find_all_node(node, xpath)
    if length(nodes) != 1 do
      raise "not single node #{length(nodes)}"
    end
    Enum.fetch!(nodes, 0)
  end

  defp get_attribute_value(%Libxml.Node{} = node) do
    %Libxml.Node{type: :attribute_node, children: children} = Libxml.Node.extract(node)
    %Libxml.Node{type: :text_node, more: %Libxml.Node.Default{content: content}} = Libxml.Node.extract(children)
    %Libxml.Char{content: content} = Libxml.Char.extract(content)
    content
  end

  defp resolve_reference(root, reference, uri_resolver) do
    uri = find_single_node(reference, "@URI")
    uri_value = get_attribute_value(uri)
    cond do
      uri_value == "" ->
        root
      String.starts_with?(uri_value, "#xpointer(") ->
        raise "XPointer references are not supported"
      String.starts_with?(uri_value, "#") ->
        id_attributes = ["Id", "ID", "id", "xml:id"]

        try do
          for id_attribute <- id_attributes do
            xpath_query = "//*[@*[local-name()='#{id_attribute}']='#{String.trim_leading(uri_value, "#")}']"
            results = find_all_node(root, xpath_query)
            case length(results) do
              0 -> :continue
              1 -> throw Enum.fetch!(results, 0)
              _ -> raise "Ambiguous reference URI #{uri_value} resolved to #{length(results)} nodes"
            end
          end
          raise "Unable to resolve reference URI: #{uri_value}"
        catch
          value -> value
        end
      true ->
        if uri_resolver == nil do
          raise "External URI dereferencing is not configured: #{uri_value}"
        end
        result = uri_resolver.(uri_value)
        if result == nil do
          raise "Unable to resolve reference URI: #{uri_value}"
        end
        result
    end
  end

  defp apply_c14n(payload, algorithm, inclusive_ns_prefixes) do
    case algorithm do
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"              -> SignXML.C14N.c14n(payload, :c14n_1_0, inclusive_ns_prefixes, false)
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" -> SignXML.C14N.c14n(payload, :c14n_1_0, inclusive_ns_prefixes, true)
      "http://www.w3.org/2001/10/xml-exc-c14n#"             -> SignXML.C14N.c14n(payload, :c14n_exclusive_1_0, inclusive_ns_prefixes, false)
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" -> SignXML.C14N.c14n(payload, :c14n_exclusive_1_0, inclusive_ns_prefixes, true)
      "http://www.w3.org/2006/12/xml-c14n11"              -> SignXML.C14N.c14n(payload, :c14n_1_1, inclusive_ns_prefixes, false)
      "http://www.w3.org/2006/12/xml-c14n11#WithComments" -> SignXML.C14N.c14n(payload, :c14n_1_1, inclusive_ns_prefixes, true)
      _ -> payload
    end
  end


  defp apply_transforms(payload, transforms_node, signature, c14n_algorithm) do
    transforms =
      if transforms_node == nil do
        []
      else
        find_all_node(transforms_node, "*[local-name()='Transform']")
      end

    has_enveloped_signature = fn transform ->
      value = transform
              |> find_single_node("@Algorithm")
              |> get_attribute_value()
      value == "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    end

    has_base64 = fn transform ->
      value = transform
              |> find_single_node("@Algorithm")
              |> get_attribute_value()
      value == "http://www.w3.org/2000/09/xmldsig#base64"
    end

    if is_binary(payload) do
      payload
    else
      payload = Libxml.Node.extract(payload)
      Libxml.safe_doc_copy_node(payload, payload.doc, :recursive, fn payload ->
        payload =
          if Enum.any?(transforms, has_enveloped_signature) do
            signature = find_single_node(payload, ".//*[local-name()='Signature']")
            Libxml.unlink_node(signature)
            Libxml.free_node(signature)
            payload
          else
            payload
          end
        payload =
          if Enum.any?(transforms, has_base64) do
            {:string, b64content} = find_all(payload, "string(text())")
            Base.decode64!(b64content)
          else
            payload
          end

        payload =
          Enum.reduce(transforms, payload, fn transform, payload ->
            inclusive_namespaces_prefix_list = find_single_or_zero_node(transform, "./*[local-name()='InclusiveNamespaces']/@PrefixList")
            inclusive_ns_prefixes = if inclusive_namespaces_prefix_list == nil do
              []
            else
              inclusive_namespaces_prefix_list
              |> get_attribute_value()
              |> String.split(" ")
            end

            algorithm = transform
                        |> find_single_node("@Algorithm")
                        |> get_attribute_value()
            apply_c14n(payload, algorithm, inclusive_ns_prefixes)
          end)

        if is_binary(payload) do
          payload
        else
          payload = apply_c14n(payload, c14n_algorithm, [])
          unless is_binary(payload) do
            raise "not applied c14n"
          end
          payload
        end
      end)
    end
  end

  defp get_digest_algorithm("http://www.w3.org/2000/09/xmldsig#sha1"), do: :sha
  defp get_digest_algorithm("http://www.w3.org/2001/04/xmlenc#sha256"), do: :sha256
  defp get_digest_algorithm("http://www.w3.org/2001/04/xmldsig-more#sha224"), do: :sha224
  defp get_digest_algorithm("http://www.w3.org/2001/04/xmldsig-more#sha384"), do: :sha384
  defp get_digest_algorithm("http://www.w3.org/2001/04/xmlenc#sha512"), do: :sha512

  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), do: {:rsa, :sha256}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"), do: {:ecdsa, :sha256}
  defp get_signature_digest_method("http://www.w3.org/2000/09/xmldsig#dsa-sha1"), do: {:dss, :sha}
  defp get_signature_digest_method("http://www.w3.org/2000/09/xmldsig#rsa-sha1"), do: {:rsa, :sha}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"), do: {:rsa, :sha224}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"), do: {:rsa, :sha384}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"), do: {:rsa, :sha512}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"), do: {:ecdsa, :sha}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"), do: {:ecdsa, :sha224}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"), do: {:ecdsa, :sha384}
  defp get_signature_digest_method("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"), do: {:ecdsa, :sha512}
  defp get_signature_digest_method("http://www.w3.org/2009/xmldsig11#dsa-sha256"), do: {:dss, :sha256}

  defp get_hmac_algorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1"), do: :sha
  defp get_hmac_algorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"), do: :sha256
  defp get_hmac_algorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"), do: :sha384
  defp get_hmac_algorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"), do: :sha512
  defp get_hmac_algorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"), do: :sha224

  defp check_digest(root, opts) do
    uri_resolver = Keyword.get(opts, :uri_resolver)

    signature = find_single_node(root, "//*[local-name()='Signature']")
    signed_info = find_single_node(signature, "*[local-name()='SignedInfo']")

    c14n_algorithm = signed_info
                     |> find_single_node("*[local-name()='CanonicalizationMethod']/@Algorithm")
                     |> get_attribute_value()

    for reference <- find_all_node(signed_info, "*[local-name()='Reference']") do
      transforms = find_single_or_zero_node(reference, "*[local-name()='Transforms']")
      digest_algorithm = find_single_node(reference, "*[local-name()='DigestMethod']/@Algorithm")
      {:string, digest_value} = find_all(reference, "string(*[local-name()='DigestValue'][text()])")
      digest_value = Base.decode64!(digest_value, ignore: :whitespace)
      payload = resolve_reference(root, reference, uri_resolver)
      payload_c14n = apply_transforms(payload, transforms, signature, c14n_algorithm)

      digest_algorithm = digest_algorithm |> get_attribute_value() |> get_digest_algorithm()
      digest = :crypto.hash(digest_algorithm, payload_c14n)
      if digest != digest_value do
        raise "Digest mismatch"
      end

      payload_resolver = Keyword.get(opts, :payload_resolver)
      if payload_resolver == nil do
        payload_c14n
      else
        Libxml.safe_read_memory(payload_c14n, fn doc ->
          payload_resolver.(doc)
        end)
      end
    end
  end

  require Record
  Record.defrecordp :otpCertificate, Record.extract(:"OTPCertificate", from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp :otpTBSCertificate, Record.extract(:"OTPTBSCertificate", from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp :rsaPublicKey, Record.extract(:"RSAPublicKey", from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp :otpSubjectPublicKeyInfo, Record.extract(:"OTPSubjectPublicKeyInfo", from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp :publicKeyAlgorithm, Record.extract(:"PublicKeyAlgorithm", from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp :dssSigValue, Record.extract(:"Dss-Sig-Value", from_lib: "public_key/include/public_key.hrl")

  defp get_public_key(der_certs, opts) do
    der_cert = List.last(der_certs)

    trusted_cert =
      case Keyword.fetch(opts, :ca_pem_file) do
        {:ok, ca_pem_file} ->
          [{_, trusted_cert, _} | _] = :public_key.pem_decode(File.read!(ca_pem_file))
          trusted_cert
        :error ->
          [trusted_cert | _] = :certifi.cacerts()
          trusted_cert
      end
    {:ok, {_public_key_info, _policy_tree}} = :public_key.pkix_path_validation(trusted_cert, der_certs, [])

    otp = :public_key.pkix_decode_cert(der_cert, :otp)
    tbs = otpCertificate(otp, :tbsCertificate)
    public_key = otpTBSCertificate(tbs, :subjectPublicKeyInfo)
    subject = otpSubjectPublicKeyInfo(public_key, :subjectPublicKey)

    subject
  end

  defp get_bytes(key_value, tag) do
    {:string, b64value} = find_all(key_value, "string(*[local-name()='#{tag}']/text())")
    Base.decode64!(b64value, ignore: :whitespace)
  end

  defp verify_signature(root, opts) do
    signature = find_single_node(root, ".//*[local-name()='Signature']")
    signed_info = find_single_node(signature, "*[local-name()='SignedInfo']")

    c14n_algorithm = signed_info
                     |> find_single_node("*[local-name()='CanonicalizationMethod']/@Algorithm")
                     |> get_attribute_value()
    signed_info_c14n = apply_c14n(signed_info, c14n_algorithm, [])

    signature_value = find_single_node(signature, "*[local-name()='SignatureValue']/text()")
    signature_alg = signed_info
                    |> find_single_node("*[local-name()='SignatureMethod']/@Algorithm")
                    |> get_attribute_value()
    raw_signature = signature_value
                    |> Libxml.Node.extract()
                    |> Map.fetch!(:more)
                    |> Map.fetch!(:content)
                    |> Libxml.Char.extract()
                    |> Map.fetch!(:content)
                    |> Base.decode64!(ignore: :whitespace)

    x509_data = find_single_or_zero_node(signature, "*[local-name()='KeyInfo']/*[local-name()='X509Data']")
    require_x509 = Keyword.get(opts, :require_x509, true)
    cond do
      x509_data != nil || Keyword.has_key?(opts, :x509_cert) || require_x509 ->
        der_certs =
          case Keyword.fetch(opts, :x509_cert) do
            :error ->
              if x509_data == nil do
                raise "Expected a X.509 certificate based signature"
              else
                certs = find_all_node(x509_data, "*[local-name()='X509Certificate']/text()")
                if length(certs) == 0 do
                  raise "Expected to find an X509Certificate element in the signature (X509SubjectName, X509SKI are not supported)"
                end

                x509certs =
                  Enum.map(certs, fn cert ->
                    cert
                    |> Libxml.Node.extract()
                    |> Map.fetch!(:more)
                    |> Map.fetch!(:content)
                    |> Libxml.Char.extract()
                    |> Map.fetch!(:content)
                  end)

                der_certs = Enum.map(x509certs, fn x509cert ->
                  Base.decode64!(x509cert, ignore: :whitespace)
                end)

                der_certs
              end
            {:ok, x509_cert} ->
              cert_entries = :public_key.pem_decode(x509_cert)
              der_certs = Enum.map(cert_entries, fn {_, der_cert, _} -> der_cert end)
              der_certs
          end

        public_key = get_public_key(der_certs, opts)

        {_algorithm, digest_method} = get_signature_digest_method(signature_alg)
        unless :public_key.verify(signed_info_c14n, digest_method, raw_signature, public_key) do
          raise "Signature verification failed"
        end
      String.contains?(signature_alg, "hmac-sha") ->
        hmac_key = Keyword.fetch!(opts, :hmac_key)
        algorithm = get_hmac_algorithm(signature_alg)
        signature = :crypto.hmac(algorithm, hmac_key, signed_info_c14n)
        if raw_signature != signature do
          raise "Signature mismatch (HMAC)"
        end
      true ->
        key_value = find_single_node(signature, "*[local-name()='KeyInfo']/*[local-name()='KeyValue']")

        cond do
          String.contains?(signature_alg, "dsa-") ->
            dsa_key_value = find_single_node(key_value, "*[local-name()='DSAKeyValue']")
            p = get_bytes(dsa_key_value, "P")
            q = get_bytes(dsa_key_value, "Q")
            g = get_bytes(dsa_key_value, "G")
            y = get_bytes(dsa_key_value, "Y")
            {:dss, digest_method} = get_signature_digest_method(signature_alg)

            length = div(byte_size(raw_signature), 2)
            <<r :: binary-size(length), s :: binary-size(length)>> = raw_signature
            entity = dssSigValue(r: :crypto.bytes_to_integer(r), s: :crypto.bytes_to_integer(s))
            der_signature = :public_key.der_encode(:"Dss-Sig-Value", entity)

            unless :crypto.verify(:dss, digest_method, signed_info_c14n, der_signature, [p, q, g, y]) do
              raise "Signature mismatch (DSA)"
            end
          String.contains?(signature_alg, "rsa-") ->
            rsa_key_value = find_single_node(key_value, "*[local-name()='RSAKeyValue']")
            modules = get_bytes(rsa_key_value, "Modulus")
            exponent = get_bytes(rsa_key_value, "Exponent")
            {:rsa, digest_method} = get_signature_digest_method(signature_alg)
            unless :crypto.verify(:rsa, digest_method, signed_info_c14n, raw_signature, [exponent, modules]) do
              raise "Signature mismatch (RSA)"
            end
          true ->
            raise "not implemented"
        end
    end
  end

  @valid_opts [:x509_cert,
               :require_x509,
               :ca_pem_file,
               :uri_resolver,
               :payload_resolver,
               :hmac_key]
  def verify(xml, opts \\ []) do
    # check opts
    invalid_opts = Enum.filter(opts, fn {key, _} -> key not in @valid_opts end)
    if length(invalid_opts) != 0 do
      raise "invalid opts: #{inspect invalid_opts}"
    end

    Libxml.safe_read_memory(xml, fn doc ->
      result = check_digest(doc, opts)
      verify_signature(doc, opts)
      result
    end)
  end
end
