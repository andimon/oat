defmodule Oat.OAuth2.Syntax do
  @moduledoc """
  Validators for the protocol element syntax in RFC 6749 Appendix A.

  Every function takes a binary and returns a boolean. Non-binaries return `false`.

      VSCHAR            = %x20-7E
      NQCHAR            = %x21 / %x23-5B / %x5D-7E
      NQSCHAR           = %x20-21 / %x23-5B / %x5D-7E
      UNICODECHARNOCRLF = %x09 / %x20-7E / %x80-D7FF / %xE000-FFFD / %x10000-10FFFF
  """

  @doc "`client_id` and `client_secret` (A.1, A.2): `*VSCHAR`."
  def client_id?(value), do: all?(value, &vschar?/1, 0)
  def client_secret?(value), do: all?(value, &vschar?/1, 0)

  @doc "`state` (A.5), `code` (A.11), `access_token` (A.12), `refresh_token` (A.17): `1*VSCHAR`."
  def state?(value), do: all?(value, &vschar?/1, 1)
  def code?(value), do: all?(value, &vschar?/1, 1)
  def access_token?(value), do: all?(value, &vschar?/1, 1)
  def refresh_token?(value), do: all?(value, &vschar?/1, 1)

  @doc "A single `scope-token` (A.4): `1*NQCHAR`."
  def scope_token?(value), do: all?(value, &nqchar?/1, 1)

  @doc "`scope` (A.4): `scope-token *( SP scope-token )`."
  def scope?(value), do: space_delimited?(value, &scope_token?/1)

  @doc "`response_type` (A.3): `response-name *( SP response-name )`."
  def response_type?(value),
    do: space_delimited?(value, &all?(&1, fn c -> response_char?(c) end, 1))

  @doc "`error` and `error_description` (A.7, A.8): `1*NQSCHAR`."
  def error?(value), do: all?(value, &nqschar?/1, 1)
  def error_description?(value), do: all?(value, &nqschar?/1, 1)

  @doc "`grant_type` (A.10) and `token_type` (A.13): `name / URI-reference`."
  def grant_type?(value), do: name?(value) or uri_reference?(value)
  def token_type?(value), do: name?(value) or uri_reference?(value)

  @doc "`expires_in` (A.14): `1*DIGIT`."
  def expires_in?(value), do: all?(value, &(&1 in ?0..?9), 1)

  @doc "`username` and `password` (A.15, A.16): `*UNICODECHARNOCRLF`."
  def username?(value), do: unicode_no_crlf?(value)
  def password?(value), do: unicode_no_crlf?(value)

  @doc "`param-name` for extension parameters (A.18) and `grant-name`/`type-name`: `1*name-char`."
  def name?(value), do: all?(value, &name_char?/1, 1)

  @doc "`redirect_uri` (A.6) and `error_uri` (A.9): an RFC 3986 URI-reference."
  def uri_reference?(value) when is_binary(value) and value != "" do
    String.valid?(value) and match?({:ok, _}, URI.new(value))
  end

  def uri_reference?(_), do: false

  defp unicode_no_crlf?(value) when is_binary(value) do
    String.valid?(value) and
      value |> String.to_charlist() |> Enum.all?(&unicode_char_no_crlf?/1)
  end

  defp unicode_no_crlf?(_), do: false

  defp space_delimited?(value, token?) when is_binary(value) and value != "" do
    value |> :binary.split(" ", [:global]) |> Enum.all?(token?)
  end

  defp space_delimited?(_, _), do: false

  defp all?(value, char?, min) when is_binary(value) and byte_size(value) >= min do
    for(<<c <- value>>, reduce: true, do: (acc -> acc and char?.(c)))
  end

  defp all?(_, _, _), do: false

  ## Character classes

  defp vschar?(c), do: c in 0x20..0x7E
  defp nqchar?(c), do: c == 0x21 or c in 0x23..0x5B or c in 0x5D..0x7E
  defp nqschar?(c), do: c == 0x20 or nqchar?(c)
  defp alnum?(c), do: c in ?a..?z or c in ?A..?Z or c in ?0..?9
  defp name_char?(c), do: alnum?(c) or c in [?-, ?., ?_]
  defp response_char?(c), do: alnum?(c) or c == ?_

  defp unicode_char_no_crlf?(c) do
    c == 0x09 or c in 0x20..0x7E or c in 0x80..0xD7FF or c in 0xE000..0xFFFD or
      c in 0x10000..0x10FFFF
  end
end
