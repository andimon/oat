defmodule OatWeb.PageController do
  use OatWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
