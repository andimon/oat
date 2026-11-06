defmodule Oat.OAuth2.ClientsTest do
  use Oat.DataCase, async: true

  import Oat.OAuth2Fixtures

  alias Oat.OAuth2.{ClientAuth, Clients}

  describe "register/2" do
    test "a confidential client gets a secret, stored only as a hash" do
      # Arrange
      attrs = %{name: "App", redirect_uris: ["https://a.example/cb"]}

      # Act
      {:ok, client, secret} = Clients.register(attrs)

      # Assert
      assert is_binary(secret)
      assert client.secret_hash
      refute client.secret_hash == secret
      assert Clients.get(client.id).id == client.id
    end

    test "a public client has no secret" do
      # Arrange
      attrs = %{name: "App", redirect_uris: ["https://a.example/cb"]}

      # Act
      {:ok, client, secret} = Clients.register(attrs, confidential: false)

      # Assert
      assert secret == nil
      assert client.secret_hash == nil
    end

    test "redirect URIs must be absolute and have no fragment" do
      # Arrange
      cases = [[], ["/cb"], ["https://a.example/cb#frag"]]

      # Act
      results = for uris <- cases, do: Clients.register(%{name: "App", redirect_uris: uris})

      # Assert
      for result <- results do
        assert {:error, %Ecto.Changeset{errors: errors}} = result
        assert Keyword.has_key?(errors, :redirect_uris)
      end
    end

    test "redirect URIs must not already carry authorization response parameters" do
      # Arrange
      uris =
        for name <- ~w(code state error error_description error_uri),
            do: "https://a.example/cb?#{name}=x"

      # Act
      results = for uri <- uris, do: Clients.register(%{name: "App", redirect_uris: [uri]})

      # Assert
      for result <- results do
        assert {:error, %Ecto.Changeset{errors: [redirect_uris: _]}} = result
      end
    end

    test "redirect URIs may keep other query parameters" do
      # Act
      result = Clients.register(%{name: "App", redirect_uris: ["https://a.example/cb?app=1"]})

      # Assert
      assert {:ok, _client, _secret} = result
    end

    test "default scopes must be a subset of the client's scopes" do
      # Arrange
      attrs = %{
        name: "App",
        redirect_uris: ["https://a.example/cb"],
        scopes: ["read"],
        default_scopes: ["admin"]
      }

      # Act
      result = Clients.register(attrs)

      # Assert
      assert {:error, %Ecto.Changeset{errors: [default_scopes: _]}} = result
    end
  end

  describe "authenticate/2" do
    setup do
      {client, secret} = client_fixture()
      {public, nil} = client_fixture(%{}, confidential: false)
      %{client: client, secret: secret, public: public}
    end

    test "accepts the secret in the Authorization header", %{client: client, secret: secret} do
      # Arrange
      header = ClientAuth.encode_basic({client.id, secret})

      # Act
      result = Clients.authenticate(header, %{})

      # Assert
      assert {:ok, %{id: id}} = result
      assert id == client.id
    end

    test "accepts the secret in the body", %{client: client, secret: secret} do
      # Arrange
      params = %{"client_id" => client.id, "client_secret" => secret}

      # Act
      result = Clients.authenticate(nil, params)

      # Assert
      assert {:ok, _client} = result
    end

    test "rejects a wrong secret or unknown client", %{client: client} do
      # Arrange
      requests = [
        {ClientAuth.encode_basic({client.id, "wrong"}), %{}},
        {nil, %{"client_id" => client.id, "client_secret" => "wrong"}},
        {ClientAuth.encode_basic({"nobody", "secret"}), %{}},
        {nil, %{"client_id" => "nobody"}}
      ]

      # Act
      results = for {header, params} <- requests, do: Clients.authenticate(header, params)

      # Assert
      for result <- results, do: assert({:error, %{error: :invalid_client}} = result)
    end

    test "credentials outside VSCHAR are rejected", %{client: client, secret: secret} do
      # Arrange
      requests = [
        {nil, %{"client_id" => client.id, "client_secret" => secret <> "\n"}},
        {nil, %{"client_id" => "é", "client_secret" => secret}},
        {nil, %{"client_id" => "é"}}
      ]

      # Act
      results = for {header, params} <- requests, do: Clients.authenticate(header, params)

      # Assert
      for result <- results, do: assert({:error, %{error: :invalid_client}} = result)
    end

    test "a confidential client cannot skip authentication", %{client: client} do
      # Arrange
      params = %{"client_id" => client.id}

      # Act
      result = Clients.authenticate(nil, params)

      # Assert
      assert {:error, %{error: :invalid_client}} = result
    end

    test "a public client identifies itself with client_id", %{public: public} do
      # Arrange
      params = %{"client_id" => public.id}

      # Act
      result = Clients.authenticate(nil, params)

      # Assert
      assert {:ok, %{id: id}} = result
      assert id == public.id
    end

    test "a public client cannot present a secret", %{public: public} do
      # Arrange
      params = %{"client_id" => public.id, "client_secret" => "anything"}

      # Act
      result = Clients.authenticate(nil, params)

      # Assert
      assert {:error, %{error: :invalid_client}} = result
    end

    test "no client identification at all is invalid_client" do
      # Act
      result = Clients.authenticate(nil, %{})

      # Assert
      assert {:error, %{error: :invalid_client}} = result
    end

    test "using two authentication methods is invalid_request",
         %{client: client, secret: secret} do
      # Arrange
      header = ClientAuth.encode_basic({client.id, secret})
      params = %{"client_id" => client.id, "client_secret" => secret}

      # Act
      result = Clients.authenticate(header, params)

      # Assert
      assert {:error, %{error: :invalid_request}} = result
    end
  end
end
