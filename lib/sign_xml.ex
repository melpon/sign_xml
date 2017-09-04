defmodule SignXML do
  def verify(xml, opts \\ []) do
    SignXML.Verifier.verify(xml, opts)
  end
end
