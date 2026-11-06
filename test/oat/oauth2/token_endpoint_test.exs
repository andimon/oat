defmodule Oat.OAuth2.TokenEndpointTest do
  use Oat.DataCase, async: true

  import Oat.OAuth2Fixtures

  alias Oat.OAuth2.TokenEndpoint

  setup do
    {client, secret} = client_fixture()
    %{client: client, auth: basic_auth(client, secret), code: code_fixture(client)}
  end

  test "issues a token for a valid authorization code request", %{auth: auth, code: code} do
    # Arrange
    body = form(%{"grant_type" => "authorization_code", "code" => code})

    # Act
    result = TokenEndpoint.handle(auth, body)

    # Assert
    assert {:ok, %{"access_token" => _, "token_type" => "Bearer"}} = result
  end

  test "rejects bad requests with the right error", %{auth: auth, code: code} do
    # Arrange
    cases = [
      {"grant_type=authorization_code&code=#{code}&code=#{code}", :invalid_request},
      {form(%{"code" => code}), :invalid_request},
      {form(%{"grant_type" => "a b"}), :invalid_request},
      {form(%{"grant_type" => "password"}), :unsupported_grant_type},
      {form(%{"grant_type" => "refresh_token"}), :unsupported_grant_type},
      {form(%{"grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer"}),
       :unsupported_grant_type}
    ]

    # Act
    results = for {body, expected} <- cases, do: {expected, TokenEndpoint.handle(auth, body)}

    # Assert
    for {expected, result} <- results, do: assert({:error, %{error: ^expected}} = result)
  end

  test "a repeated parameter with an odd name is a clean invalid_request", %{auth: auth} do
    # Act
    result = TokenEndpoint.handle(auth, "grant_type=authorization_code&%C3%A9=1&%C3%A9=2")

    # Assert
    assert {:error, %{error: :invalid_request, description: "A parameter is repeated"}} = result
  end

  test "an empty body still requires client authentication" do
    # Act
    result = TokenEndpoint.handle(nil, nil)

    # Assert
    assert {:error, %{error: :invalid_client}} = result
  end
end
