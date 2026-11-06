defmodule OatWeb.CacheBodyReader do
  @moduledoc """
  A `Plug.Parsers` `:body_reader` that keeps the raw body in
  `conn.assigns.raw_body`.

  RFC 6749 §3.2 (https://www.rfc-editor.org/rfc/rfc6749#section-3.2) forbids
  repeating a parameter, but `Plug.Parsers` keeps only the last value of a
  repeated one. The token endpoint decodes the raw body itself with
  `Oat.OAuth2.Params.decode/1` to catch repeats.

  Every parsed body is kept, not only token requests, so the reader does not
  depend on the route. Only the urlencoded and JSON parsers use it; multipart
  bodies are not kept.
  """

  @doc "A `Plug.Parsers` `:body_reader`."
  def read_body(conn, opts) do
    with {status, body, conn} when status in [:ok, :more] <- Plug.Conn.read_body(conn, opts) do
      {status, body, Plug.Conn.assign(conn, :raw_body, [body | conn.assigns[:raw_body] || []])}
    end
  end

  @doc "The cached raw body, or `nil` if none was read."
  def raw_body(%Plug.Conn{assigns: %{raw_body: chunks}}),
    do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  def raw_body(%Plug.Conn{}), do: nil
end
