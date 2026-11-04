defmodule Oat.OAuth2.ClientAuth do
  @moduledoc """
  Client password authentication (RFC 6749 §2.3.1).

  The client sends its credentials either in an HTTP Basic `Authorization`
  header or as `client_id`/`client_secret` body parameters. In the header the
  id and secret are form-urlencoded (Appendix B) before Base64 encoding.
  A client must not use more than one method in the same request (§2.3).
  """

  @type credentials :: {client_id :: String.t(), client_secret :: String.t()}

  @doc """
  Encodes credentials as a Basic `Authorization` header value.

      iex> Oat.OAuth2.ClientAuth.encode_basic({"s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"})
      "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"
  """
  @spec encode_basic(credentials()) :: String.t()
  def encode_basic({id, secret}) do
    "Basic " <>
      Base.encode64(URI.encode_www_form(id) <> ":" <> URI.encode_www_form(secret))
  end

  @doc """
  Decodes a Basic `Authorization` header value. The scheme name is case-insensitive.
  """
  @spec decode_basic(String.t()) :: {:ok, credentials()} | {:error, :invalid_client}
  def decode_basic(<<scheme::binary-size(6), encoded::binary>>) when is_binary(encoded) do
    with "basic " <- String.downcase(scheme),
         {:ok, decoded} <- Base.decode64(String.trim(encoded)),
         [id, secret] <- :binary.split(decoded, ":"),
         {:ok, id} <- www_form_decode(id),
         {:ok, secret} <- www_form_decode(secret),
         true <- id != "" do
      {:ok, {id, secret}}
    else
      _ -> {:error, :invalid_client}
    end
  end

  def decode_basic(_), do: {:error, :invalid_client}

  @doc """
  Extracts client credentials from a request.

  * `authorization` is the `Authorization` header value, or `nil`.
  * `params` are the decoded body parameters.

  Returns `{:ok, {:basic, creds}}`, `{:ok, {:body, creds}}`, `{:ok, {:public, client_id}}`
  for a client that sends only `client_id` (§3.2.1), or `{:ok, :none}`.
  Using both the header and body credentials is an `:invalid_request`.
  """
  @spec extract(String.t() | nil, map()) ::
          {:ok,
           {:basic, credentials()}
           | {:body, credentials()}
           | {:public, String.t()}
           | :none}
          | {:error, :invalid_request | :invalid_client}
  def extract(authorization, params) do
    body = Map.take(params, ["client_id", "client_secret"])

    case {authorization, body} do
      {nil, %{"client_id" => id, "client_secret" => secret}} ->
        {:ok, {:body, {id, secret}}}

      {nil, %{"client_id" => id}} ->
        {:ok, {:public, id}}

      {nil, _} ->
        {:ok, :none}

      {header, body} when map_size(body) == 0 ->
        with {:ok, c} <- decode_basic(header), do: {:ok, {:basic, c}}

      {_header, %{"client_secret" => _}} ->
        {:error, :invalid_request}

      {header, %{"client_id" => id}} ->
        basic_matching_id(header, id)
    end
  end

  # A client may repeat its client_id in the body alongside Basic auth, as long as it matches.
  defp basic_matching_id(header, id) do
    case decode_basic(header) do
      {:ok, {^id, _} = creds} -> {:ok, {:basic, creds}}
      {:ok, _} -> {:error, :invalid_request}
      error -> error
    end
  end

  @doc """
  Compares a presented secret with the stored one in constant time.
  """
  @spec secret_matches?(String.t(), String.t()) :: boolean()
  def secret_matches?(presented, stored) when is_binary(presented) and is_binary(stored) do
    Plug.Crypto.secure_compare(presented, stored)
  end

  def secret_matches?(_, _), do: false

  @doc """
  The `WWW-Authenticate` header value to send with a 401 `invalid_client`
  response when the client tried to authenticate with the `Authorization` header (§5.2).
  """
  @spec www_authenticate(String.t()) :: String.t()
  def www_authenticate(realm \\ "oat"), do: ~s(Basic realm="#{realm}")

  defp www_form_decode(value) do
    {:ok, URI.decode_www_form(value)}
  rescue
    ArgumentError -> :error
  end
end
