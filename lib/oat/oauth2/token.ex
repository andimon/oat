defmodule Oat.OAuth2.Token do
  @moduledoc """
  Generation and lifetime of credentials issued by the authorization server:
  authorization codes, access tokens and refresh tokens (RFC 6749 §4.1.2,
  §1.4, §1.5, §10.10).

  Generated values must be impossible to guess (§10.10). Here they are 256 bits
  from `:crypto.strong_rand_bytes/1`, encoded with URL-safe Base64 without
  padding, so they fit the `1*VSCHAR` syntax and need no escaping in URLs.
  """

  @default_bytes 32

  @doc """
  Generates a random credential. `bytes` is the amount of entropy (default 32,
  i.e. 256 bits; §10.10 requires at least 128 bits, so anything under 16 raises).
  """
  @spec generate(pos_integer()) :: String.t()
  def generate(bytes \\ @default_bytes) when is_integer(bytes) and bytes >= 16 do
    bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end

  @doc """
  Hashes a credential for storage, so a database leak does not expose usable
  codes or tokens. Look tokens up by this hash.
  """
  @spec hash(String.t()) :: String.t()
  def hash(token) when is_binary(token) do
    :sha256 |> :crypto.hash(token) |> Base.url_encode64(padding: false)
  end

  @doc """
  The expiry time for a credential issued at `issued_at` with a lifetime of
  `lifetime` seconds. Authorization codes should live 10 minutes at most (§4.1.2).
  """
  @spec expires_at(DateTime.t(), pos_integer()) :: DateTime.t()
  def expires_at(%DateTime{} = issued_at, lifetime) when is_integer(lifetime) and lifetime > 0 do
    DateTime.add(issued_at, lifetime, :second)
  end

  @doc "Whether a credential that expires at `expires_at` has expired at `now`."
  @spec expired?(DateTime.t(), DateTime.t()) :: boolean()
  def expired?(%DateTime{} = expires_at, %DateTime{} = now \\ DateTime.utc_now()) do
    DateTime.compare(now, expires_at) != :lt
  end

  @doc """
  Seconds left until `expires_at`, for the `expires_in` response parameter (§5.1).
  Never negative.
  """
  @spec expires_in(DateTime.t(), DateTime.t()) :: non_neg_integer()
  def expires_in(%DateTime{} = expires_at, %DateTime{} = now \\ DateTime.utc_now()) do
    max(DateTime.diff(expires_at, now, :second), 0)
  end
end
