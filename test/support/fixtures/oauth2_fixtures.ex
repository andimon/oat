defmodule Oat.OAuth2Fixtures do
  @moduledoc "Test data for `Oat.OAuth2`."

  alias Oat.OAuth2.{AuthorizationCodeGrant, ClientAuth, Clients}

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
    |> form()
  end

  @doc """
  Issues an authorization code for `client`, as if `resource_owner` approved
  the request built by `authorize_query/2` from `params`.
  """
  def code_fixture(client, params \\ %{}, resource_owner \\ "alice") do
    {:ok, request} = AuthorizationCodeGrant.validate(authorize_query(client, params))
    {:ok, uri} = AuthorizationCodeGrant.approve(request, resource_owner)
    redirect_params(uri)["code"]
  end

  @doc "Encodes parameters as a form body or query string, leaving out `nil` values."
  def form(params), do: params |> Oat.OAuth2.Params.compact() |> URI.encode_query(:www_form)

  @doc "The Basic `Authorization` header value for a client."
  def basic_auth(client, secret), do: ClientAuth.encode_basic({client.id, secret})

  @doc "Reads the query parameters from a redirect URI."
  def redirect_params(uri), do: uri |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
end
