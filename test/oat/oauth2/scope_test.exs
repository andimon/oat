defmodule Oat.OAuth2.ScopeTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Scope

  doctest Scope

  test "parse/1 treats an omitted scope as empty and rejects bad syntax" do
    assert Scope.parse(nil) == {:ok, MapSet.new()}
    assert Scope.parse("a b a") == {:ok, MapSet.new(["a", "b"])}
    assert Scope.parse("") == {:error, :invalid_scope}
  end

  test "format/1 sorts and drops duplicates, and returns nil for an empty scope" do
    assert Scope.format(MapSet.new(["write", "read"])) == "read write"
    assert Scope.format(MapSet.new()) == nil
  end

  test "resolve/3 uses the default for an empty request" do
    allowed = MapSet.new(["read", "write"])
    default = MapSet.new(["read"])

    assert Scope.resolve(MapSet.new(), allowed, default) == {:ok, default}
    assert Scope.resolve(MapSet.new(), allowed) == {:error, :invalid_scope}
  end

  test "resolve/3 rejects scopes outside the allowed set" do
    allowed = MapSet.new(["read"])

    assert Scope.resolve(MapSet.new(["read"]), allowed) == {:ok, MapSet.new(["read"])}
    assert Scope.resolve(MapSet.new(["read", "admin"]), allowed) == {:error, :invalid_scope}
  end

  test "changed?/2 ignores order" do
    refute Scope.changed?(MapSet.new(["a", "b"]), MapSet.new(["b", "a"]))
    assert Scope.changed?(MapSet.new(["a", "b"]), MapSet.new(["a"]))
  end
end
