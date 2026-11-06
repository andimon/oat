defmodule Oat.OAuth2.TokenEndpoint do
  @moduledoc """
  Token requests: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) §3.2,
  §4.1.3, §5.

  `handle/2` decodes the form body, authenticates the client and dispatches on
  `grant_type`. The HTTP side (media type, status, headers) is in
  `OatWeb.TokenController`.
  """

  alias Oat.OAuth2.{AuthorizationCodeGrant, Clients, Error, Params, Syntax}

  @doc """
  Handles a token request.

  * `authorization` is the `Authorization` header value, or `nil`.
  * `body` is the raw `application/x-www-form-urlencoded` body. It is decoded
    here, not by `Plug.Parsers`, so repeated parameters can be rejected (§3.2).

  Returns the token response parameters (§5.1) or the error (§5.2).
  """
  @spec handle(String.t() | nil, String.t() | nil) :: {:ok, map()} | {:error, Error.t()}
  def handle(authorization, body) do
    with {:ok, params} <- decode(body),
         {:ok, client} <- Clients.authenticate(authorization, params) do
      grant(client, params)
    end
  end

  defp decode(body) do
    case Params.decode(body) do
      {params, []} -> {:ok, params}
      {_params, [name | _]} -> {:error, Error.repeated(name)}
    end
  end

  defp grant(client, %{"grant_type" => "authorization_code"} = params),
    do: AuthorizationCodeGrant.exchange(client, params)

  # grant_type is a name or an absolute URI for extension grants (A.10, §4.5).
  defp grant(_client, %{"grant_type" => grant_type}) do
    if Syntax.grant_type?(grant_type),
      do: Error.error(:unsupported_grant_type, "Unsupported grant type"),
      else: Error.error(:invalid_request, "The grant_type parameter is invalid")
  end

  defp grant(_client, _params),
    do: Error.error(:invalid_request, "The grant_type parameter is missing")
end
