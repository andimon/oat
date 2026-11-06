defmodule OatWeb.Router do
  use OatWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {OatWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/oauth", OatWeb do
    pipe_through :browser

    get "/authorize", AuthorizeController, :new
    post "/authorize", AuthorizeController, :create
  end

  # No pipeline: token requests need not send an Accept header, RFC 6749 §4.1.3
  # (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3),
  # and use client authentication instead of a session or CSRF token.
  scope "/oauth", OatWeb do
    post "/token", TokenController, :create
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:oat, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: OatWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end

    scope "/dev", OatWeb do
      pipe_through :browser

      get "/sign_in", DevSessionController, :new
      post "/sign_in", DevSessionController, :create
    end
  end
end
