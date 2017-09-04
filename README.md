# SignXML

SignXML is an implementation of the W3C [XML Signature](https://en.wikipedia.org/wiki/XML_Signature) standard in Elixir.

The library based on [Python SignXML implementation](https://signxml.readthedocs.io/en/latest/).

Now the library has only XML validation.

```elixir
xml = File.read!("example.xml")
[result] = SignXML.verify(xml, ca_pem_file: "cacert.pem")

IO.puts result
# output:
#   <saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ...> ... </saml2:Assertion>
```
