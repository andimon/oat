defmodule OatWeb.TokenControllerTest do
  use OatWeb.ConnCase, async: true

  import Oat.OAuth2Fixtures

  alias Oat.OAuth2.{AuthorizationCodeGrant, ClientAuth}

  setup do
    {client, secret} = client_fixture()
    %{client: client, secret: secret, code: issue_code(client)}
  end

  defp issue_code(client) do
    {:ok, request} = AuthorizationCodeGrant.validate(authorize_query(client))
    {:ok, uri} = AuthorizationCodeGrant.approve(request, "alice")
    redirect_params(uri)["code"]
  end

  defp token_request(conn, body, headers \\ []) do
    conn
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> then(fn conn ->
      Enum.reduce(headers, conn, fn {k, v}, c -> put_req_header(c, k, v) end)
    end)
    |> post("/oauth/token", body)
  end

  defp form(params), do: URI.encode_query(params, :www_form)

  test "exchanges a code for an access token with Basic authentication",
       %{conn: conn, client: client, secret: secret, code: code} do
    # Arrange
    body = form(%{"grant_type" => "authorization_code", "code" => code})
    auth = [{"authorization", ClientAuth.encode_basic({client.id, secret})}]

    # Act
    conn = token_request(conn, body, auth)

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
    code = issue_code(public)
    body = form(%{"grant_type" => "authorization_code", "code" => code, "client_id" => public.id})

    # Act
    conn = token_request(conn, body)

    # Assert
    assert %{"access_token" => _} = json_response(conn, 200)
  end

  test "failed Basic authentication is a 401 with WWW-Authenticate",
       %{conn: conn, client: client, code: code} do
    # Arrange
    body = form(%{"grant_type" => "authorization_code", "code" => code})
    auth = [{"authorization", ClientAuth.encode_basic({client.id, "wrong"})}]

    # Act
    conn = token_request(conn, body, auth)

    # Assert
    assert %{"error" => "invalid_client"} = json_response(conn, 401)
    assert [~s(Basic realm=) <> _] = get_resp_header(conn, "www-authenticate")
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "a reused code is invalid_grant",
       %{conn: conn, client: client, secret: secret, code: code} do
    # Arrange
    body = form(%{"grant_type" => "authorization_code", "code" => code})
    auth = [{"authorization", ClientAuth.encode_basic({client.id, secret})}]
    token_request(conn, body, auth)

    # Act
    conn = token_request(build_conn(), body, auth)

    # Assert
    assert %{"error" => "invalid_grant"} = json_response(conn, 400)
  end

  test "rejects bad requests with the right error",
       %{conn: conn, client: client, secret: secret, code: code} do
    # Arrange
    auth = [{"authorization", ClientAuth.encode_basic({client.id, secret})}]

    cases = [
      {"grant_type=authorization_code&code=#{code}&code=#{code}", "invalid_request"},
      {form(%{"code" => code}), "invalid_request"},
      {form(%{"grant_type" => "password"}), "unsupported_grant_type"}
    ]

    # Act
    results = for {body, expected} <- cases, do: {expected, token_request(conn, body, auth)}

    # Assert
    for {expected, conn} <- results do
      assert %{"error" => ^expected} = json_response(conn, 400)
    end
  end

  test "requires a form-encoded body", %{conn: conn, client: client, secret: secret} do
    # Arrange
    body = Jason.encode!(%{"grant_type" => "authorization_code"})

    # Act
    conn =
      conn
      |> put_req_header("content-type", "application/json")
      |> put_req_header("authorization", ClientAuth.encode_basic({client.id, secret}))
      |> post("/oauth/token", body)

    # Assert
    assert %{"error" => "invalid_request"} = json_response(conn, 400)
  end
end
