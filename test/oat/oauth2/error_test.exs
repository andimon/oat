defmodule Oat.OAuth2.ErrorTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Error

  doctest Error

  test "to_params/1 leaves out empty fields" do
    error = Error.new(:access_denied, state: "xyz")
    assert Error.to_params(error) == %{"error" => "access_denied", "state" => "xyz"}

    error = Error.new(:invalid_grant, description: "Code expired", uri: "https://docs.example/e")

    assert Error.to_params(error) == %{
             "error" => "invalid_grant",
             "error_description" => "Code expired",
             "error_uri" => "https://docs.example/e"
           }
  end

  test "new/2 rejects descriptions outside the allowed characters" do
    assert_raise ArgumentError, fn -> Error.new(:invalid_request, description: ~s(a "quote")) end
    assert_raise ArgumentError, fn -> Error.new(:invalid_request, description: "naïve") end
  end

  test "status/2" do
    assert Error.status(Error.new(:invalid_grant)) == 400
    assert Error.status(Error.new(:invalid_client)) == 400
    assert Error.status(Error.new(:invalid_client), header_auth?: true) == 401
  end

  test "lists the registered error codes per endpoint" do
    assert :access_denied in Error.authorization_codes()
    assert :invalid_grant in Error.token_codes()
    refute :invalid_grant in Error.authorization_codes()
  end
end
