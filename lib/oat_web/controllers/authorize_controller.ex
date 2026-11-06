defmodule OatWeb.AuthorizeController do
  @moduledoc """
  The authorization endpoint: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) §3.1, §4.1.1, §4.1.2.

  `GET /oauth/authorize` validates the authorization request, makes sure the
  resource owner is signed in (see `OatWeb.ResourceOwner`) and shows the
  consent page. The page posts the decision, with the original query string,
  to `POST /oauth/authorize`, which validates the request again and redirects
  back to the client.
  """

  use OatWeb, :controller

  alias Oat.OAuth2.AuthorizationCodeGrant
  alias OatWeb.ResourceOwner

  require Logger

  # The consent page must not be framed, against clickjacking (§10.13).
  plug :put_secure_browser_headers, %{
    "x-frame-options" => "DENY",
    "content-security-policy" => "frame-ancestors 'none'"
  }

  def new(conn, _params) do
    with_request(conn, conn.query_string, fn conn, request, _owner ->
      render(conn, :consent, request: request, query: conn.query_string, page_title: "Authorize")
    end)
  end

  def create(conn, %{"request" => query} = params) when is_binary(query) do
    with_request(conn, query, fn conn, request, owner ->
      case params["decision"] do
        "approve" ->
          redirect(conn, external: approve(request, owner))

        "deny" ->
          redirect(conn, external: AuthorizationCodeGrant.deny(request))

        _ ->
          bad_request(conn, "invalid_request", "Choose to allow or deny the request")
      end
    end)
  end

  def create(conn, _params),
    do: bad_request(conn, "invalid_request", "The authorization request is missing")

  # The request was valid, so a failure from here on goes back to the client as
  # server_error rather than a 500 the client never sees (§4.1.2.1).
  defp approve(request, owner) do
    {:ok, uri} = AuthorizationCodeGrant.approve(request, owner)
    uri
  rescue
    exception ->
      Logger.error(Exception.format(:error, exception, __STACKTRACE__))

      AuthorizationCodeGrant.error_redirect(
        request,
        :server_error,
        "The authorization server could not issue a code"
      )
  end

  defp with_request(conn, query, fun) do
    case AuthorizationCodeGrant.validate(query) do
      {:ok, request} ->
        resource_owner = ResourceOwner.impl()

        case resource_owner.fetch(conn) do
          {:ok, owner} -> fun.(conn, request, owner)
          :error -> resource_owner.authenticate(conn, "/oauth/authorize?" <> query)
        end

      {:error, :redirect, uri} ->
        redirect(conn, external: uri)

      {:error, :show, error} ->
        bad_request(conn, Atom.to_string(error.error), error.description)
    end
  end

  defp bad_request(conn, error, description) do
    conn
    |> put_status(:bad_request)
    |> render(:error, error: error, description: description, page_title: "Authorization error")
  end
end
