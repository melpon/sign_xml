defmodule SignXMLTest do
  use ExUnit.Case

  def run_tests(testcases, base_dir) do
    for {xml_file, result, opts} <- testcases do
      xml = File.read!("#{base_dir}/#{xml_file}")
      try do
        IO.puts "start: #{xml_file}"
        SignXML.verify(xml, opts)
        assert result == :ok
      rescue
        error ->
          if result != :error do
            IO.puts "failed: #{xml_file}"
            IO.puts Exception.format(:error, error, System.stacktrace())
          end
          assert result == :error
      end
    end
  end

  @rsa_opts [ca_pem_file: "test/interop/aleksey-xmldsig-01/cacert.pem", require_x509: false]
  @hmac_opts [hmac_key: "secret", require_x509: false]
  @aleksey_xmldsig_01 [
    {"enveloping-dsa-x509chain.xml", :error, []}, # todo cases
    {"enveloping-expired-cert.xml", :error, []}, # error: expired
    {"enveloping-md5-hmac-md5-64.xml", :error, @hmac_opts}, # error: md5
    {"enveloping-md5-hmac-md5.xml", :error, @hmac_opts}, # error: md5
    {"enveloping-md5-rsa-md5.xml", :error, @rsa_opts}, # error: md5
    {"enveloping-ripemd160-hmac-ripemd160-64.xml", :error, @hmac_opts}, # error: ripemd160
    {"enveloping-ripemd160-hmac-ripemd160.xml", :error, @hmac_opts}, # error: ripemd160
    {"enveloping-ripemd160-rsa-ripemd160.xml", :error, @rsa_opts}, # error: ripemd160
    {"enveloping-rsa-x509chain.xml", :ok, @rsa_opts},
    {"enveloping-sha1-hmac-sha1-64.xml", :error, @hmac_opts}, # error: "HMACOutputLength" in sig.decode("utf-8")
    {"enveloping-sha1-hmac-sha1.xml", :ok, @hmac_opts},
    {"enveloping-sha1-rsa-sha1.xml", :ok, @rsa_opts},
    {"enveloping-sha224-hmac-sha224-64.xml", :error, @hmac_opts}, # error: "HMACOutputLength" in sig.decode("utf-8")
    {"enveloping-sha224-hmac-sha224.xml", :ok, @hmac_opts},
    {"enveloping-sha224-rsa-sha224.xml", :ok, @rsa_opts},
    {"enveloping-sha256-hmac-sha256-64.xml", :error, @hmac_opts}, # error: "HMACOutputLength" in sig.decode("utf-8")
    {"enveloping-sha256-hmac-sha256.xml", :ok, @hmac_opts},
    {"enveloping-sha256-rsa-sha256.xml", :ok, @rsa_opts},
    {"enveloping-sha384-hmac-sha384-64.xml", :error, @hmac_opts}, # error: "HMACOutputLength" in sig.decode("utf-8")
    {"enveloping-sha384-hmac-sha384.xml", :ok, @hmac_opts},
    {"enveloping-sha384-rsa-sha384.xml", :ok, @rsa_opts},
    {"enveloping-sha512-hmac-sha512-64.xml", :error, @hmac_opts}, # error: "HMACOutputLength" in sig.decode("utf-8")
    {"enveloping-sha512-hmac-sha512.xml", :ok, @hmac_opts},
    {"enveloping-sha512-rsa-sha512.xml", :ok, @rsa_opts},
    {"x509data-sn-test.xml", :error, []}, # unsupported cases
    {"x509data-test.xml", :error, []}, # unsupported cases
    {"xpointer-hmac.xml", :error, []}, # unsupported cases
  ]

  test "aleksey_xmldsig_01" do
    run_tests(@aleksey_xmldsig_01, "test/interop/aleksey-xmldsig-01")
  end

  @rsa_opts [ca_pem_file: "test/interop/aleksey-xmldsig-01-enveloped/cacert.pem"]
  @aleksey_xmldsig_01_enveloped [
    {"enveloped-sha256-rsa-sha256-test-1.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-2.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-3.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-4.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-5.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-6.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-7.xml", :ok, @rsa_opts},
    {"enveloped-sha256-rsa-sha256-test-8.xml", :ok, @rsa_opts},
    {"invalid_enveloped_transform.xml", :error, @rsa_opts},
  ]

  test "aleksey_xmldsig_01_enveloped" do
    run_tests(@aleksey_xmldsig_01_enveloped, "test/interop/aleksey-xmldsig-01-enveloped")
  end

  @opts [require_x509: false]
  @hmac_opts [hmac_key: "secret", require_x509: false]
  @merlin_xmldsig_twenty_three [
    {"signature-enveloped-dsa.xml", :ok, @opts},
    {"signature-enveloping-b64-dsa.xml", :ok, @opts},
    {"signature-enveloping-dsa.xml", :ok, @opts},
    {"signature-enveloping-hmac-sha1-40.xml", :error, @hmac_opts},
    {"signature-enveloping-hmac-sha1.xml", :ok, @hmac_opts},
    {"signature-enveloping-rsa.xml", :ok, @opts},
    {"signature-external-b64-dsa.xml", :error, @opts},
    {"signature-external-dsa.xml", :error, @opts},
    {"signature-keyname.xml", :error, @opts},
    {"signature-retrievalmethod-rawx509crt.xml", :error, @opts},
    {"signature-x509-crt-crl.xml", :error, @opts},
    {"signature-x509-crt.xml", :error, @opts},
    {"signature-x509-is.xml", :error, @opts},
    {"signature-x509-ski.xml", :error, @opts},
    {"signature-x509-sn.xml", :error, @opts},
    {"signature.xml", :error, @opts},
  ]

  test "merlin_xmldsig_twenty_three" do
    run_tests(@merlin_xmldsig_twenty_three, "test/interop/merlin-xmldsig-twenty-three")
  end

  def uri_resolver(name) do
    cond do
      name == "document.xml" -> File.read!("test/interop/phaos-xmldsig-three/document.xml")
      name == "http://www.ietf.org/rfc/rfc3161.txt" -> File.read!("test/interop/rfc3161.txt")
    end
  end
  @opts [uri_resolver: &SignXMLTest.uri_resolver/1, hmac_key: "test", require_x509: false]

  @phaos_xmldsig_three [
    {"signature-big.xml", :error, @opts}, # todo case
    {"signature-dsa-detached.xml", :error, @opts}, # expired
    {"signature-dsa-enveloped.xml", :error, @opts}, # expired
    {"signature-dsa-enveloping.xml", :error, @opts}, # expired
    # {"signature-dsa-manifest.xml", :ok, @opts}, # ???
    {"signature-hmac-md5-c14n-enveloping.xml", :error, @opts}, # md5 not supported
    {"signature-hmac-sha1-40-c14n-comments-detached.xml", :error, @opts}, # length
    {"signature-hmac-sha1-40-exclusive-c14n-comments-detached.xml", :error, @opts}, # length
    {"signature-hmac-sha1-exclusive-c14n-comments-detached.xml", :ok, @opts},
    {"signature-hmac-sha1-exclusive-c14n-enveloped.xml", :ok, @opts},
    # {"signature-rsa-detached-b64-transform.xml", :ok, @opts}, # ???
    {"signature-rsa-detached-xpath-transform.xml", :error, @opts}, # Digest mismatch for reference 0
    # {"signature-rsa-detached-xslt-transform-bad-retrieval-method.xml", :ok, @opts}, # ???
    {"signature-rsa-detached-xslt-transform-retrieval-method.xml", :error, @opts}, # Expected to find either KeyValue or X509Data XML element in KeyInfo
    # {"signature-rsa-detached-xslt-transform.xml", :ok, @opts}, # ???
    {"signature-rsa-detached.xml", :error, @opts}, # expired
    {"signature-rsa-enveloped-bad-digest-val.xml", :error, @opts},
    {"signature-rsa-enveloped-bad-sig.xml", :error, @opts},
    {"signature-rsa-enveloped.xml", :error, @opts}, # expired
    {"signature-rsa-enveloping.xml", :error, @opts}, # expired
    {"signature-rsa-manifest-x509-data-cert-chain.xml", :error, @opts}, # expired
    {"signature-rsa-manifest-x509-data-cert.xml", :error, @opts}, # expired
    {"signature-rsa-manifest-x509-data-issuer-serial.xml", :error, @opts}, # unsupported
    {"signature-rsa-manifest-x509-data-ski.xml", :error, @opts}, # unsupported
    {"signature-rsa-manifest-x509-data-subject-name.xml", :error, @opts}, # unsupported
    {"signature-rsa-manifest-x509-data.xml", :error, @opts}, # unsupported
    # {"signature-rsa-manifest.xml", :ok, @opts}, # ???
    {"signature-rsa-xpath-transform-enveloped.xml", :error, @opts}, # expired
  ]

  test "phaos_xmldsig_three" do
    run_tests(@phaos_xmldsig_three, "test/interop/phaos-xmldsig-three")
  end

  # @opts [x509_cert: File.read!("test/interop/pyXMLSecurity/test.pem")]
  @pyxml_security [
    # {"edugain.xml", :ok, @opts}, # ???
    # {"SAML_assertion1.xml", :ok, @opts}, # ???
    # {"SAML_assertion_sha256.xml", :ok, @opts}, # ???
  ]

  test "pyxml_security" do
    run_tests(@pyxml_security, "test/interop/pyXMLSecurity")
  end

  @xml_crypto [
    {"signature_with_inclusivenamespaces.xml", :ok, [ca_pem_file: "test/interop/xml-crypto/signature_with_inclusivenamespaces.pem"]},
    # {"windows_store_signature.xml", :ok, [x509_cert: File.read!("test/interop/xml-crypto/windows_store_certificate.pem")]}, # {:error, {:bad_cert, :invalid_issuer}}
    # {"wsfederation_metadata.xml", :ok, [ca_pem_file: "test/interop/xml-crypto/wsfederation_metadata.pem"]}, # cert expired
  ]

  test "xml_crypto" do
    run_tests(@xml_crypto, "test/interop/xml-crypto")
  end
end
