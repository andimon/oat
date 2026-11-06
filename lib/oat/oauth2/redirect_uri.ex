defmodule Oat.OAuth2.RedirectURI do
  @moduledoc """
  Redirection endpoint handling (RFC 6749 §3.1.2, §4.1.2).
  """

  @doc """
  Checks that a redirection URI is an absolute URI without a fragment (§3.1.2).
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(uri) when is_binary(uri) do
    case URI.new(uri) do
      {:ok, %URI{scheme: scheme, fragment: nil}} when is_binary(scheme) -> true
      _ -> false
    end
  end

  def valid?(_), do: false

  @doc """
  Picks the redirection URI for an authorization request (§3.1.2.3, §4.1.1).

  * `requested` is the `redirect_uri` parameter, or `nil` when it was left out.
  * `registered` is the list of URIs registered for the client.

  When the request leaves the parameter out, the client must have exactly one
  registered URI. When the request includes it, it must match a registered URI
  by simple string comparison (RFC 3986 §6.2.1).

  On error the server must not redirect to the URI; it shows the error to the
  resource owner instead (§4.1.2.1).
  """
  @spec resolve(String.t() | nil, [String.t()]) ::
          {:ok, String.t()} | {:error, :missing_redirect_uri | :invalid_redirect_uri}
  def resolve(nil, [only]),
    do: if(valid?(only), do: {:ok, only}, else: {:error, :invalid_redirect_uri})

  def resolve(nil, _registered), do: {:error, :missing_redirect_uri}

  def resolve(requested, registered) do
    if valid?(requested) and requested in registered do
      {:ok, requested}
    else
      {:error, :invalid_redirect_uri}
    end
  end

  @doc """
  Adds response parameters to the query of a redirection URI, keeping any query
  it already has (§3.1.2, §4.1.2). Parameters with `nil` values are left out.
  Values are encoded with `application/x-www-form-urlencoded` (Appendix B).

      iex> Oat.OAuth2.RedirectURI.append("https://c.example/cb?x=1", code: "abc", state: nil)
      "https://c.example/cb?x=1&code=abc"
  """
  @spec append(String.t(), Enumerable.t()) :: String.t()
  def append(uri, params) do
    encoded = params |> Enum.reject(fn {_, v} -> is_nil(v) end) |> URI.encode_query(:www_form)
    uri = URI.parse(uri)

    URI.to_string(%{uri | query: join_query(uri.query, encoded)})
  end

  defp join_query(existing, ""), do: existing
  defp join_query(nil, encoded), do: encoded
  defp join_query("", encoded), do: encoded
  defp join_query(existing, encoded), do: existing <> "&" <> encoded
end
