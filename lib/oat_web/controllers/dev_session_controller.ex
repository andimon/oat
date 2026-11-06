defmodule OatWeb.DevSessionController do
  @moduledoc """
  Development-only sign in for `OatWeb.ResourceOwner.Session`: type any name
  to become that resource owner. Routed only when `:dev_routes` is enabled.
  """

  use OatWeb, :controller

  alias OatWeb.ResourceOwner.Session

  def new(conn, params) do
    render(conn, :new, return_to: safe_return_to(params["return_to"]), page_title: "Sign in")
  end

  def create(conn, %{"name" => name} = params) when name != "" do
    conn
    |> configure_session(renew: true)
    |> put_session(Session.session_key(), name)
    |> redirect(to: safe_return_to(params["return_to"]))
  end

  def create(conn, params), do: new(conn, params)

  # Only local paths, so this cannot be used as an open redirect.
  defp safe_return_to("/" <> rest = path) do
    if String.starts_with?(rest, ["/", "\\"]), do: "/", else: path
  end

  defp safe_return_to(_), do: "/"
end
