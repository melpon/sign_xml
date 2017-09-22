defmodule SignXML.Mixfile do
  use Mix.Project

  def project do
    [
      app: :sign_xml,
      version: "1.0.3",
      elixir: "~> 1.4",
      description: "An implementation of the W3C XML Signature standard in Elixir",
      package: [maintainers: ["melpon"],
                licenses: ["MIT"],
                links: %{"GitHub" => "https://github.com/melpon/sign_xml"}],
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:libxml, "~> 1.0"},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
    ]
  end
end
