defmodule OatWeb.AuthorizeControllerTest do
  use OatWeb.ConnCase, async: true

  import Oat.OAuth2Fixtures

  setup %{conn: conn} do
    {client, _secret} = client_fixture()
    signed_in = Plug.Test.init_test_session(conn, %{"resource_owner_id" => "alice"})
    %{client: client, signed_in: signed_in}
  end

  describe "GET /oauth/authorize" do
    test "shows the consent page to a signed-in resource owner",
         %{signed_in: conn, client: client} do
      # Arrange
      query = authorize_query(client, %{"scope" => "read write"})

      # Act
      conn = get(conn, "/oauth/authorize?" <> query)

      # Assert
      html = html_response(conn, 200)
      assert html =~ "Example App"
      assert html =~ "read"
      assert html =~ "write"
      assert get_resp_header(conn, "x-frame-options") == ["DENY"]
    end

    test "asks the resource owner to sign in first", %{conn: conn, client: client} do
      # Arrange
      query = authorize_query(client)

      # Act
      conn = get(conn, "/oauth/authorize?" <> query)

      # Assert
      assert response(conn, 401) =~ "Sign in required"
    end

    test "shows an error instead of redirecting to an unregistered redirect_uri",
         %{signed_in: conn, client: client} do
      # Arrange
      query = authorize_query(client, %{"redirect_uri" => "https://evil.example/cb"})

      # Act
      conn = get(conn, "/oauth/authorize?" <> query)

      # Assert
      html = html_response(conn, 400)
      assert html =~ "invalid_request"
      assert html =~ "The redirect_uri is invalid"
    end

    test "redirects other errors to the client, before asking to sign in",
         %{conn: conn, client: client} do
      # Arrange
      query = authorize_query(client, %{"response_type" => "token"})

      # Act
      conn = get(conn, "/oauth/authorize?" <> query)

      # Assert
      assert %{"error" => "unsupported_response_type", "state" => "xyz"} =
               conn |> redirected_to(302) |> redirect_params()
    end
  end

  describe "POST /oauth/authorize" do
    test "approving redirects back with a code", %{signed_in: conn, client: client} do
      # Arrange
      params = %{"request" => authorize_query(client), "decision" => "approve"}

      # Act
      conn = post(conn, "/oauth/authorize", params)

      # Assert
      location = redirected_to(conn, 302)
      assert String.starts_with?(location, redirect_uri() <> "?")
      assert %{"code" => _, "state" => "xyz"} = redirect_params(location)
    end

    test "denying redirects back with access_denied", %{signed_in: conn, client: client} do
      # Arrange
      params = %{"request" => authorize_query(client), "decision" => "deny"}

      # Act
      conn = post(conn, "/oauth/authorize", params)

      # Assert
      assert %{"error" => "access_denied"} = conn |> redirected_to(302) |> redirect_params()
    end

    test "requires a signed-in resource owner", %{conn: conn, client: client} do
      # Arrange
      params = %{"request" => authorize_query(client), "decision" => "approve"}

      # Act
      conn = post(conn, "/oauth/authorize", params)

      # Assert
      assert response(conn, 401)
    end

    test "validates the request again", %{signed_in: conn, client: client} do
      # Arrange
      query = authorize_query(client, %{"redirect_uri" => "https://evil.example/cb"})
      params = %{"request" => query, "decision" => "approve"}

      # Act
      conn = post(conn, "/oauth/authorize", params)

      # Assert
      assert html_response(conn, 400) =~ "The redirect_uri is invalid"
    end

    test "rejects a missing request or decision", %{signed_in: conn, client: client} do
      # Act
      no_request = post(conn, "/oauth/authorize", %{"decision" => "approve"})
      no_decision = post(conn, "/oauth/authorize", %{"request" => authorize_query(client)})

      # Assert
      assert html_response(no_request, 400) =~ "invalid_request"
      assert html_response(no_decision, 400) =~ "invalid_request"
    end
  end
end
