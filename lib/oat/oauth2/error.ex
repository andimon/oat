defmodule Oat.OAuth2.Error do
  @moduledoc """
  OAuth 2.0 error responses: RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) §4.1.2.1, §5.2.

  The same struct serves both endpoints:

  * Authorization endpoint errors go back to the client as redirect parameters
    (`to_params/1` with `Oat.OAuth2.RedirectURI.append/2`), with `state` copied
    from the request.
  * Token endpoint errors are a JSON body (`to_params/1`) with the status from
    `status/1`.
  """

  alias Oat.OAuth2.{Params, Syntax}

  @enforce_keys [:error]
  defstruct [:error, :description, :uri, :state]

  @type code :: atom()
  @type t :: %__MODULE__{
          error: code(),
          description: String.t() | nil,
          uri: String.t() | nil,
          state: String.t() | nil
        }

  @doc """
  Builds an error. Raises `ArgumentError` if the description or URI would break
  the character set rules (§4.1.2.1, Appendix A.8, A.9), since those values come
  from server code rather than from the client.

  Options: `:description`, `:uri`, `:state`.
  """
  @spec new(code(), keyword()) :: t()
  def new(code, opts \\ []) when is_atom(code) do
    error = struct!(__MODULE__, [error: code] ++ Keyword.take(opts, [:description, :uri, :state]))

    unless Syntax.error?(Atom.to_string(code)),
      do: raise(ArgumentError, "invalid error code #{inspect(code)}")

    if error.description && not Syntax.error_description?(error.description),
      do: raise(ArgumentError, "error description must be printable ASCII without \" or \\")

    if error.uri && not Syntax.uri_reference?(error.uri),
      do: raise(ArgumentError, "error uri must be a URI reference")

    error
  end

  @doc "`{:error, error}` for an error with a description, the usual failure result."
  @spec error(code(), String.t()) :: {:error, t()}
  def error(code, description), do: {:error, new(code, description: description)}

  @doc """
  The `invalid_request` error for a repeated parameter (§3.1, §3.2).

  The name comes from the request, so it is named only when it is a valid
  `param-name` (A.18). Anything else could break the description's character
  set (A.8).

      iex> Oat.OAuth2.Error.repeated("scope").description
      "The scope parameter is repeated"

      iex> Oat.OAuth2.Error.repeated(~s(a"b)).description
      "A parameter is repeated"
  """
  @spec repeated(String.t()) :: t()
  def repeated(name) do
    description =
      if Syntax.name?(name),
        do: "The #{name} parameter is repeated",
        else: "A parameter is repeated"

    new(:invalid_request, description: description)
  end

  @doc """
  The response parameters, leaving out `nil` values. Use as a JSON body at the
  token endpoint, or as redirect parameters at the authorization endpoint.
  """
  @spec to_params(t()) :: %{String.t() => String.t()}
  def to_params(%__MODULE__{} = error) do
    Params.compact([
      {"error", Atom.to_string(error.error)},
      {"error_description", error.description},
      {"error_uri", error.uri},
      {"state", error.state}
    ])
  end

  @doc """
  HTTP status for a token endpoint error (§5.2). `invalid_client` is 401 when
  the client authenticated with the `Authorization` header, and otherwise may be
  400 or 401; pass `header_auth?: true` when the header was used.
  """
  @spec status(t(), keyword()) :: 400 | 401
  def status(error, opts \\ [])

  def status(%__MODULE__{error: :invalid_client}, opts),
    do: if(opts[:header_auth?], do: 401, else: 400)

  def status(%__MODULE__{}, _opts), do: 400
end
