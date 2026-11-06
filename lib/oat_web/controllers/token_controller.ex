defmodule OatWeb.TokenController do
  @moduledoc """
  The token endpoint: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) §3.2, §4.1.3, §4.1.4, §5.

  Only `POST` with an `application/x-www-form-urlencoded` body is accepted.
  Parameters are decoded from the raw body (see `OatWeb.CacheBodyReader`) so
  repeated parameters can be rejected (§3.2).
  """

  use OatWeb, :controller

  alias Oat.OAuth2.{
    AuthorizationCodeGrant,
    ClientAuth,
    Clients,
    Error,
    Params,
    Syntax,
    TokenResponse
  }

  alias OatWeb.CacheBodyReader

  def create(conn, _params) do
    authorization = conn |> get_req_header("authorization") |> List.first()

    result =
      with {:ok, params} <- decode(conn),
           {:ok, client} <- Clients.authenticate(authorization, params) do
        grant(client, params)
      end

    case result do
      {:ok, body} ->
        send_json(conn, 200, body)

      {:error, %Error{} = error} ->
        status = Error.status(error, header_auth?: authorization != nil)

        conn
        |> maybe_challenge(status)
        |> send_json(status, Error.to_params(error))
    end
  end

  defp decode(conn) do
    with :ok <- check_content_type(conn),
         {:ok, params} <- conn |> CacheBodyReader.raw_body() |> Params.decode() do
      {:ok, params}
    else
      {:error, {:repeated, name}, _params} ->
        {:error, Error.new(:invalid_request, description: Error.repeated_description(name))}

      {:error, :content_type} ->
        {:error,
         Error.new(:invalid_request,
           description: "Use the application/x-www-form-urlencoded format"
         )}
    end
  end

  defp check_content_type(conn) do
    # Media types are case-insensitive: RFC 9110 §8.3.1
    # (https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1).
    with [value | _] <- get_req_header(conn, "content-type"),
         {:ok, "application", "x-www-form-urlencoded", _params} <-
           Plug.Conn.Utils.content_type(value) do
      :ok
    else
      _ -> {:error, :content_type}
    end
  end

  defp grant(client, %{"grant_type" => "authorization_code"} = params),
    do: AuthorizationCodeGrant.exchange(client, params)

  # grant_type is a name or an absolute URI for extension grants (A.10, §4.5).
  defp grant(_client, %{"grant_type" => grant_type}) do
    if Syntax.grant_type?(grant_type),
      do: {:error, Error.new(:unsupported_grant_type, description: "Unsupported grant type")},
      else:
        {:error, Error.new(:invalid_request, description: "The grant_type parameter is invalid")}
  end

  defp grant(_client, _params),
    do: {:error, Error.new(:invalid_request, description: "The grant_type parameter is missing")}

  # A 401 must say how to authenticate (§5.2).
  defp maybe_challenge(conn, 401),
    do: put_resp_header(conn, "www-authenticate", ClientAuth.www_authenticate())

  defp maybe_challenge(conn, _status), do: conn

  defp send_json(conn, status, body) do
    conn
    |> merge_resp_headers(TokenResponse.headers())
    |> send_resp(status, Jason.encode!(body))
  end
end
