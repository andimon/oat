defmodule Oat.OAuth2.ParamsTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Params

  doctest Params

  test "decode/1 drops empty values before checking for repeats" do
    assert Params.decode("scope=&scope=read") == {:ok, %{"scope" => "read"}}
    assert Params.decode(nil) == {:ok, %{}}

    assert Params.decode("redirect_uri=https%3A%2F%2Fc.example%2Fcb") ==
             {:ok, %{"redirect_uri" => "https://c.example/cb"}}
  end

  test "require/2 returns values in order or the first missing name" do
    params = %{"grant_type" => "authorization_code", "code" => "abc"}

    assert Params.require(params, ["grant_type", "code"]) == {:ok, ["authorization_code", "abc"]}

    assert Params.require(params, ["code", "redirect_uri"]) ==
             {:error, {:missing, "redirect_uri"}}
  end

  test "response_type/1 rejects bad syntax" do
    assert Params.response_type("code") == {:ok, MapSet.new(["code"])}
    assert Params.response_type("code  token") == {:error, :invalid_request}
  end
end
