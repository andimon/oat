defmodule Oat.OAuth2Fixtures do
  @moduledoc "Test data for `Oat.OAuth2`."

  alias Oat.OAuth2.Clients

  @redirect_uri "https://client.example.com/cb"

  def redirect_uri, do: @redirect_uri

  @doc """
  Registers a client. Returns `{client, secret}`; `secret` is `nil` when
  `confidential: false` is given.
  """
  def client_fixture(attrs \\ %{}, opts \\ []) do
    attrs =
      Enum.into(attrs, %{
        name: "Example App",
        redirect_uris: [@redirect_uri],
        scopes: ["read", "write"],
        default_scopes: ["read"]
      })

    {:ok, client, secret} = Clients.register(attrs, opts)
    {client, secret}
  end

  @doc "Builds an authorization request query string for `client`."
  def authorize_query(client, params \\ %{}) do
    %{"response_type" => "code", "client_id" => client.id, "state" => "xyz"}
    |> Map.merge(params)
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> URI.encode_query(:www_form)
  end

  @doc "Reads the query parameters from a redirect URI."
  def redirect_params(uri), do: uri |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
end
