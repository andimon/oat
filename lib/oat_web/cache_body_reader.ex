defmodule OatWeb.CacheBodyReader do
  @moduledoc """
  Keeps the raw body of token requests in `conn.assigns.raw_body`.

  RFC 6749 §3.2 forbids repeating a parameter, but `Plug.Parsers` keeps only
  the last value of a repeated one. The token endpoint decodes the raw body
  itself with `Oat.OAuth2.Params.decode/1` to catch repeats.
  """

  @paths ["/oauth/token"]

  @doc "A `Plug.Parsers` `:body_reader`."
  def read_body(conn, opts) do
    case Plug.Conn.read_body(conn, opts) do
      {status, body, conn} when status in [:ok, :more] ->
        {status, body, cache(conn, body)}

      error ->
        error
    end
  end

  @doc "The cached raw body, or `nil` if none was read."
  def raw_body(%Plug.Conn{assigns: %{raw_body: chunks}}),
    do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  def raw_body(%Plug.Conn{}), do: nil

  defp cache(%Plug.Conn{request_path: path} = conn, body) when path in @paths,
    do: Plug.Conn.assign(conn, :raw_body, [body | conn.assigns[:raw_body] || []])

  defp cache(conn, _body), do: conn
end
