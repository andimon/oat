defmodule OatWeb.ResourceOwner.Session do
  @moduledoc """
  Default `OatWeb.ResourceOwner`: the resource owner identifier is the
  `"resource_owner_id"` session value, set by whatever signs the user in.

  When nobody is signed in, it redirects to `/dev/sign_in` if the dev routes
  are enabled, and otherwise responds with 401.
  """

  @behaviour OatWeb.ResourceOwner

  import Plug.Conn

  @session_key "resource_owner_id"

  @doc "The session key that holds the resource owner identifier."
  def session_key, do: @session_key

  @impl true
  def fetch(conn) do
    case get_session(conn, @session_key) do
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> :error
    end
  end

  @impl true
  def authenticate(conn, return_to) do
    if Application.get_env(:oat, :dev_routes) do
      conn
      |> Phoenix.Controller.redirect(
        to: "/dev/sign_in?" <> URI.encode_query(return_to: return_to)
      )
      |> halt()
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(401, "Sign in required")
      |> halt()
    end
  end
end
