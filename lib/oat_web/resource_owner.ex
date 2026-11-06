defmodule OatWeb.ResourceOwner do
  @moduledoc """
  How the authorization endpoint finds out who the resource owner is
  (§3.1, §4.1.1 step B of RFC 6749, https://www.rfc-editor.org/rfc/rfc6749).

  RFC 6749 (https://www.rfc-editor.org/rfc/rfc6749) leaves the way the authorization server authenticates the resource
  owner open, so oat does not ship user accounts. The host application
  implements this behaviour and configures it:

      config :oat, OatWeb.ResourceOwner, MyApp.OAuthResourceOwner

  The default is `OatWeb.ResourceOwner.Session`.
  """

  @doc """
  Returns the identifier of the signed-in resource owner, or `:error` when
  nobody is signed in.
  """
  @callback fetch(Plug.Conn.t()) :: {:ok, String.t()} | :error

  @doc """
  Asks the resource owner to sign in, for example by redirecting to a login
  page. After signing in the user-agent should go to `return_to`, a local path
  that repeats the authorization request. The returned conn must be halted.
  """
  @callback authenticate(Plug.Conn.t(), return_to :: String.t()) :: Plug.Conn.t()

  @doc "The configured implementation."
  @spec impl() :: module()
  def impl, do: Application.get_env(:oat, __MODULE__, OatWeb.ResourceOwner.Session)
end
