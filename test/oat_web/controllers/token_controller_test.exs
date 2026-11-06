defmodule OatWeb.TokenControllerTest do
  use OatWeb.ConnCase, async: true

  import Oat.OAuth2Fixtures

  setup do
    {client, secret} = client_fixture()

    %{
      client: client,
      secret: secret,
      auth: basic_auth(client, secret),
      code: code_fixture(client)
    }
  end

  defp token_request(conn, body, opts \\ []) do
    conn =
      put_req_header(
        conn,
        "content-type",
        Keyword.get(opts, :content_type, "application/x-www-form-urlencoded")
      )

    conn =
      if auth = opts[:authorization], do: put_req_header(conn, "authorization", auth), else: conn

    post(conn, "/oauth/token", body)
  end

  defp code_grant(code), do: form(%{"grant_type" => "authorization_code", "code" => code})

  test "exchanges a code for an access token with Basic authentication",
       %{conn: conn, auth: auth, code: code} do
    # Act
    conn = token_request(conn, code_grant(code), authorization: auth)

    # Assert
    assert %{"access_token" => _, "token_type" => "Bearer", "expires_in" => 3600} =
             json_response(conn, 200)

    assert get_resp_header(conn, "cache-control") == ["no-store"]
    assert get_resp_header(conn, "pragma") == ["no-cache"]
  end

  test "accepts client credentials in the body",
       %{conn: conn, client: client, secret: secret, code: code} do
    # Arrange
    body =
      form(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "client_id" => client.id,
        "client_secret" => secret
      })

    # Act
    conn = token_request(conn, body)

    # Assert
    assert %{"access_token" => _} = json_response(conn, 200)
  end

  test "a public client sends only its client_id", %{conn: conn} do
    # Arrange
    {public, nil} = client_fixture(%{}, confidential: false)

    body =
      form(%{
        "grant_type" => "authorization_code",
        "code" => code_fixture(public),
        "client_id" => public.id
      })

    # Act
    conn = token_request(conn, body)

    # Assert
    assert %{"access_token" => _} = json_response(conn, 200)
  end

  test "failed Basic authentication is a 401 with WWW-Authenticate",
       %{conn: conn, client: client, code: code} do
    # Act
    conn = token_request(conn, code_grant(code), authorization: basic_auth(client, "wrong"))

    # Assert
    assert %{"error" => "invalid_client"} = json_response(conn, 401)
    assert [~s(Basic realm=) <> _] = get_resp_header(conn, "www-authenticate")
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "a reused code is invalid_grant", %{conn: conn, auth: auth, code: code} do
    # Arrange
    token_request(conn, code_grant(code), authorization: auth)

    # Act
    conn = token_request(build_conn(), code_grant(code), authorization: auth)

    # Assert
    assert %{"error" => "invalid_grant"} = json_response(conn, 400)
  end

  test "errors from the token request are a 400 JSON body", %{conn: conn, auth: auth} do
    # Act
    conn = token_request(conn, form(%{"grant_type" => "password"}), authorization: auth)

    # Assert
    assert %{"error" => "unsupported_grant_type"} = json_response(conn, 400)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "requires a form-encoded body", %{conn: conn, auth: auth} do
    # Arrange
    body = Jason.encode!(%{"grant_type" => "authorization_code"})

    # Act
    conn = token_request(conn, body, content_type: "application/json", authorization: auth)

    # Assert
    assert %{"error" => "invalid_request"} = json_response(conn, 400)
  end

  test "the media type is matched case-insensitively", %{conn: conn, auth: auth, code: code} do
    # Act
    conn =
      token_request(conn, code_grant(code),
        content_type: "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
        authorization: auth
      )

    # Assert
    assert %{"access_token" => _} = json_response(conn, 200)
  end
end
