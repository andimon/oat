defmodule Oat.OAuth2.ParamsTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Params

  doctest Params

  test "decode/1 drops empty values before checking for repeats" do
    assert Params.decode("scope=&scope=read") == {%{"scope" => "read"}, []}
    assert Params.decode(nil) == {%{}, []}

    assert Params.decode("redirect_uri=https%3A%2F%2Fc.example%2Fcb") ==
             {%{"redirect_uri" => "https://c.example/cb"}, []}
  end

  test "decode/1 keeps the first value and lists each repeated name once, in order" do
    assert Params.decode("client_id=s6&state=x&scope=a&state=y&scope=b&state=z") ==
             {%{"client_id" => "s6", "scope" => "a", "state" => "x"}, ["state", "scope"]}
  end

  test "response_type/1 rejects bad syntax" do
    assert Params.response_type("code") == {:ok, MapSet.new(["code"])}
    assert Params.response_type("code  token") == {:error, :invalid_request}
  end
end
