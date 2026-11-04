defmodule Oat.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      OatWeb.Telemetry,
      Oat.Repo,
      {DNSCluster, query: Application.get_env(:oat, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Oat.PubSub},
      # Start a worker by calling: Oat.Worker.start_link(arg)
      # {Oat.Worker, arg},
      # Start to serve requests, typically the last entry
      OatWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Oat.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    OatWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
