defmodule Oat.OAuth2.SyntaxTest do
  use ExUnit.Case, async: true

  alias Oat.OAuth2.Syntax

  test "client_id allows the empty string and printable ASCII only" do
    assert Syntax.client_id?("")
    assert Syntax.client_id?("s6BhdRkqt3 ~")
    refute Syntax.client_id?("tab\there")
    refute Syntax.client_id?("café")
    refute Syntax.client_id?(nil)
  end

  test "state, code and tokens need at least one VSCHAR" do
    for fun <- [:state?, :code?, :access_token?, :refresh_token?] do
      refute apply(Syntax, fun, [""])
      assert apply(Syntax, fun, ["xyz ABC"])
      refute apply(Syntax, fun, ["line\nbreak"])
    end
  end

  test "scope is space-delimited NQCHAR tokens" do
    assert Syntax.scope?("read write:all")
    refute Syntax.scope?("")
    refute Syntax.scope?("read  write")
    refute Syntax.scope?(" read")
    refute Syntax.scope?(~s(bad"quote))
    refute Syntax.scope?("bad\\slash")
  end

  test "response_type names are letters, digits and underscore" do
    assert Syntax.response_type?("code")
    assert Syntax.response_type?("code id_token")
    refute Syntax.response_type?("code-x")
    refute Syntax.response_type?("")
  end

  test "error and error_description reject quotes and backslashes but allow spaces" do
    assert Syntax.error_description?("The client is not allowed")
    refute Syntax.error_description?(~s(say "hi"))
    refute Syntax.error_description?("a\\b")
    refute Syntax.error?("")
  end

  test "grant_type and token_type accept a name or a URI" do
    assert Syntax.grant_type?("authorization_code")
    assert Syntax.grant_type?("urn:ietf:params:oauth:grant-type:saml2-bearer")
    assert Syntax.token_type?("Bearer")
    refute Syntax.grant_type?("")
  end

  test "expires_in is digits only" do
    assert Syntax.expires_in?("3600")
    refute Syntax.expires_in?("-1")
    refute Syntax.expires_in?("")
  end

  test "username and password allow Unicode but not CR or LF" do
    assert Syntax.password?("pässwörd\twith tab")
    assert Syntax.username?("")
    refute Syntax.password?("a\r\nb")
    refute Syntax.password?(<<0xFF>>)
  end
end
