defmodule OatWeb.TokenController do
  @moduledoc """
  The token endpoint: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) §3.2,
  §4.1.3, §4.1.4, §5.

  Only `POST` with an `application/x-www-form-urlencoded` body is accepted. The
  request itself is handled by `Oat.OAuth2.TokenEndpoint`, from the raw body
  kept by `OatWeb.CacheBodyReader`.
  """

  use OatWeb, :controller

  alias Oat.OAuth2.{ClientAuth, Error, TokenEndpoint, TokenResponse}
  alias OatWeb.CacheBodyReader

  def create(conn, _params) do
    authorization = conn |> get_req_header("authorization") |> List.first()

    result =
      if form_encoded?(conn),
        do: TokenEndpoint.handle(authorization, CacheBodyReader.raw_body(conn)),
        else: Error.error(:invalid_request, "Use the application/x-www-form-urlencoded format")

    case result do
      {:ok, body} ->
        respond(conn, 200, body)

      {:error, error} ->
        status = Error.status(error, header_auth?: authorization != nil)
        conn |> maybe_challenge(status) |> respond(status, Error.to_params(error))
    end
  end

  # Media types are case-insensitive: RFC 9110 §8.3.1
  # (https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1).
  defp form_encoded?(conn) do
    case get_req_header(conn, "content-type") do
      [value | _] ->
        match?(
          {:ok, "application", "x-www-form-urlencoded", _},
          Plug.Conn.Utils.content_type(value)
        )

      [] ->
        false
    end
  end

  # A 401 must say how to authenticate (§5.2).
  defp maybe_challenge(conn, 401),
    do: put_resp_header(conn, "www-authenticate", ClientAuth.www_authenticate())

  defp maybe_challenge(conn, _status), do: conn

  defp respond(conn, status, body) do
    conn
    |> merge_resp_headers(TokenResponse.headers())
    |> put_status(status)
    |> json(body)
  end
end
