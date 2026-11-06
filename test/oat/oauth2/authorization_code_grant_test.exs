defmodule Oat.OAuth2.AuthorizationCodeGrantTest do
  use Oat.DataCase, async: true

  import Oat.OAuth2Fixtures

  alias Oat.OAuth2.{AccessToken, AuthorizationCode, AuthorizationCodeGrant, Syntax, Token}

  setup do
    {client, _secret} = client_fixture()
    %{client: client}
  end

  describe "validate/1: errors shown to the resource owner (§4.1.2.1)" do
    test "missing, unknown or repeated client_id", %{client: client} do
      # Arrange
      queries = [
        "response_type=code",
        "response_type=code&client_id=nobody",
        "response_type=code&client_id=#{client.id}&client_id=#{client.id}"
      ]

      # Act
      results = Enum.map(queries, &AuthorizationCodeGrant.validate/1)

      # Assert
      for result <- results, do: assert({:error, :show, %{error: :invalid_request}} = result)
    end

    test "redirect_uri that is not registered, invalid or repeated", %{client: client} do
      # Arrange
      queries = [
        authorize_query(client, %{"redirect_uri" => "https://evil.example/cb"}),
        authorize_query(client, %{"redirect_uri" => redirect_uri() <> "/"}),
        authorize_query(client, %{"redirect_uri" => "/cb"}),
        authorize_query(client) <> "&redirect_uri=a&redirect_uri=b"
      ]

      # Act
      results = Enum.map(queries, &AuthorizationCodeGrant.validate/1)

      # Assert
      for result <- results, do: assert({:error, :show, _} = result)
    end

    test "redirect_uri left out when several are registered" do
      # Arrange
      {client, _} =
        client_fixture(%{redirect_uris: ["https://a.example/cb", "https://b.example/cb"]})

      query = authorize_query(client)

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :show, %{description: "The redirect_uri is missing"}} = result
    end
  end

  describe "validate/1: errors redirected to the client (§4.1.2.1)" do
    test "each invalid request gets its error code and the state", %{client: client} do
      # Arrange
      cases = [
        {%{"response_type" => nil}, "invalid_request"},
        {%{"response_type" => "token"}, "unsupported_response_type"},
        {%{"response_type" => "code token"}, "unsupported_response_type"},
        {%{"scope" => "admin"}, "invalid_scope"},
        {%{"scope" => "read  write"}, "invalid_scope"}
      ]

      # Act
      results =
        for {params, expected} <- cases do
          {expected, AuthorizationCodeGrant.validate(authorize_query(client, params))}
        end

      # Assert
      for {expected, result} <- results do
        assert {:error, :redirect, uri} = result
        assert String.starts_with?(uri, redirect_uri() <> "?")
        assert %{"error" => ^expected, "state" => "xyz"} = redirect_params(uri)
      end
    end

    test "a repeated parameter other than client_id or redirect_uri", %{client: client} do
      # Arrange
      query = authorize_query(client) <> "&scope=read&scope=write"

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :redirect, uri} = result
      assert %{"error" => "invalid_request"} = redirect_params(uri)
    end

    test "an invalid state is rejected and not echoed back", %{client: client} do
      # Arrange
      query = authorize_query(client, %{"state" => "bad\nstate"})

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :redirect, uri} = result
      params = redirect_params(uri)
      assert params["error"] == "invalid_request"
      refute Map.has_key?(params, "state")
    end

    test "no requested scope and no default scope" do
      # Arrange
      {client, _} = client_fixture(%{default_scopes: []})
      query = authorize_query(client)

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :redirect, uri} = result
      assert %{"error" => "invalid_scope"} = redirect_params(uri)
    end
  end

  describe "validate/1: valid requests" do
    test "falls back to the only registered redirect_uri and the default scope",
         %{client: client} do
      # Arrange
      query = authorize_query(client)

      # Act
      {:ok, request} = AuthorizationCodeGrant.validate(query)

      # Assert
      assert request.client.id == client.id
      assert request.redirect_uri == redirect_uri()
      assert request.bound_redirect_uri == nil
      assert request.requested_scopes == MapSet.new()
      assert request.scopes == MapSet.new(["read"])
      assert request.state == "xyz"
    end

    test "uses the requested redirect_uri and scope", %{client: client} do
      # Arrange
      query =
        authorize_query(client, %{"redirect_uri" => redirect_uri(), "scope" => "write read"})

      # Act
      {:ok, request} = AuthorizationCodeGrant.validate(query)

      # Assert
      assert request.bound_redirect_uri == redirect_uri()
      assert request.scopes == MapSet.new(["read", "write"])
    end

    test "state is optional and empty parameters count as omitted", %{client: client} do
      # Arrange
      query = authorize_query(client, %{"state" => nil}) <> "&scope="

      # Act
      {:ok, request} = AuthorizationCodeGrant.validate(query)

      # Assert
      assert request.state == nil
      assert request.scopes == MapSet.new(["read"])
    end
  end

  describe "approve/2 and deny/1" do
    test "approve issues a code bound to the request", %{client: client} do
      # Arrange
      {:ok, request} =
        AuthorizationCodeGrant.validate(
          authorize_query(client, %{"redirect_uri" => redirect_uri()})
        )

      # Act
      {:ok, uri} = AuthorizationCodeGrant.approve(request, "alice")

      # Assert
      assert %{"code" => code, "state" => "xyz"} = redirect_params(uri)
      stored = Repo.get_by!(AuthorizationCode, code_hash: Token.hash(code))
      assert stored.client_id == client.id
      assert stored.resource_owner_id == "alice"
      assert stored.redirect_uri == redirect_uri()
      assert stored.scopes == ["read"]
      assert DateTime.diff(stored.expires_at, DateTime.utc_now()) in 595..600
    end

    test "the code is not bound to a redirect_uri the request left out", %{client: client} do
      # Act
      code = code_fixture(client)

      # Assert
      assert Repo.get_by!(AuthorizationCode, code_hash: Token.hash(code)).redirect_uri == nil
    end

    test "deny redirects with access_denied", %{client: client} do
      # Arrange
      {:ok, request} = AuthorizationCodeGrant.validate(authorize_query(client))

      # Act
      uri = AuthorizationCodeGrant.deny(request)

      # Assert
      assert %{"error" => "access_denied", "state" => "xyz"} = redirect_params(uri)
    end
  end

  describe "exchange/2" do
    setup %{client: client} do
      code = code_fixture(client, %{"redirect_uri" => redirect_uri(), "scope" => "read write"})
      %{code: code, params: %{"code" => code, "redirect_uri" => redirect_uri()}}
    end

    test "issues an access token", %{client: client, code: code, params: params} do
      # Act
      {:ok, response} = AuthorizationCodeGrant.exchange(client, params)

      # Assert
      assert %{"access_token" => token, "token_type" => "Bearer", "expires_in" => 3600} =
               response

      # The granted scope equals the requested one, so it is left out (§5.1).
      refute Map.has_key?(response, "scope")

      stored = Repo.get_by!(AccessToken, token_hash: Token.hash(token))
      assert stored.client_id == client.id
      assert stored.resource_owner_id == "alice"
      assert stored.scopes == ["read", "write"]
      assert Repo.get_by!(AuthorizationCode, code_hash: Token.hash(code)).redeemed_at
    end

    test "returns the scope when it differs from the request, in valid syntax (A.4, A.12-A.14)",
         %{client: client} do
      # Arrange
      code = code_fixture(client)

      # Act
      {:ok, response} = AuthorizationCodeGrant.exchange(client, %{"code" => code})

      # Assert
      assert response["scope"] == "read"
      assert Syntax.scope?(response["scope"])
      assert Syntax.access_token?(response["access_token"])
      assert Syntax.token_type?(response["token_type"])
      assert Syntax.expires_in?(Integer.to_string(response["expires_in"]))
    end

    test "a code can be used only once; reuse revokes its tokens",
         %{client: client, params: params} do
      # Arrange
      {:ok, %{"access_token" => token}} = AuthorizationCodeGrant.exchange(client, params)

      # Act
      result = AuthorizationCodeGrant.exchange(client, params)

      # Assert
      assert {:error, %{error: :invalid_grant}} = result
      assert Repo.get_by!(AccessToken, token_hash: Token.hash(token)).revoked_at
    end

    test "the code must have been issued to the client", %{params: params} do
      # Arrange
      {other, _} = client_fixture()

      # Act
      result = AuthorizationCodeGrant.exchange(other, params)

      # Assert
      assert {:error, %{error: :invalid_grant}} = result
    end

    test "redirect_uri must be repeated exactly", %{client: client, params: params} do
      # Arrange
      variants = [
        Map.delete(params, "redirect_uri"),
        %{params | "redirect_uri" => redirect_uri() <> "?x=1"}
      ]

      # Act
      results = for p <- variants, do: AuthorizationCodeGrant.exchange(client, p)

      # Assert
      for result <- results, do: assert({:error, %{error: :invalid_grant}} = result)
    end

    test "an expired code is rejected", %{client: client, code: code, params: params} do
      # Arrange
      Repo.update_all(
        from(c in AuthorizationCode, where: c.code_hash == ^Token.hash(code)),
        set: [expires_at: DateTime.add(DateTime.utc_now(:second), -1)]
      )

      # Act
      result = AuthorizationCodeGrant.exchange(client, params)

      # Assert
      assert {:error, %{error: :invalid_grant}} = result
    end

    test "an unknown or missing code", %{client: client} do
      # Act
      unknown = AuthorizationCodeGrant.exchange(client, %{"code" => "nope"})
      missing = AuthorizationCodeGrant.exchange(client, %{})

      # Assert
      assert {:error, %{error: :invalid_grant}} = unknown
      assert {:error, %{error: :invalid_request}} = missing
    end
  end

  describe "syntax of request parameters (Appendix A)" do
    test "a client_id outside VSCHAR is shown as invalid, not looked up" do
      # Arrange
      query = URI.encode_query(%{"response_type" => "code", "client_id" => "a\nb"}, :www_form)

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :show, %{description: "The client_id parameter is invalid"}} = result
    end

    test "a repeated parameter whose name is not a param-name does not leak into the description",
         %{client: client} do
      # Arrange
      query = authorize_query(client) <> "&a%22=1&a%22=2"

      # Act
      result = AuthorizationCodeGrant.validate(query)

      # Assert
      assert {:error, :redirect, uri} = result

      assert %{"error" => "invalid_request", "error_description" => "A parameter is repeated"} =
               redirect_params(uri)
    end

    test "a code outside VSCHAR is invalid_request", %{client: client} do
      # Act
      result = AuthorizationCodeGrant.exchange(client, %{"code" => "a\tb"})

      # Assert
      assert {:error, %{error: :invalid_request}} = result
    end
  end

  describe "syntax of response parameters (Appendix A)" do
    test "the code and state in the redirect", %{client: client} do
      # Arrange
      {:ok, request} = AuthorizationCodeGrant.validate(authorize_query(client))

      # Act
      {:ok, uri} = AuthorizationCodeGrant.approve(request, "alice")

      # Assert
      %{"code" => code, "state" => state} = redirect_params(uri)
      assert Syntax.code?(code)
      assert Syntax.state?(state)
    end

    test "every error redirect", %{client: client} do
      # Arrange
      {:ok, request} = AuthorizationCodeGrant.validate(authorize_query(client))

      uris = [
        AuthorizationCodeGrant.deny(request),
        elem(AuthorizationCodeGrant.validate(authorize_query(client, %{"scope" => "x"})), 2)
      ]

      # Act
      params = Enum.map(uris, &redirect_params/1)

      # Assert
      for p <- params do
        assert Syntax.error?(p["error"])
        assert Syntax.error_description?(p["error_description"])
        assert p["state"] == "xyz"
      end
    end
  end
end
