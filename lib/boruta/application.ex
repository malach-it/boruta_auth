defmodule Boruta.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = cache_children() ++ [{Finch, name: OpenIDHttpClient}]

    Supervisor.start_link(children, strategy: :one_for_one, name: Boruta.Supervisor)
  end

  defp cache_children do
    case Boruta.Config.cache_backend() do
      Boruta.Cache -> [Boruta.Cache]
      _other_backend -> []
    end
  end
end
