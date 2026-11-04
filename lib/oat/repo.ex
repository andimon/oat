defmodule Oat.Repo do
  use Ecto.Repo,
    otp_app: :oat,
    adapter: Ecto.Adapters.Postgres
end
