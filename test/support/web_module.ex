defmodule Boruta.Support.WebModule do
  @moduledoc false

  def controller do
    quote do
      use Phoenix.Controller, namespace: BorutaWeb
      import Plug.Conn
    end
  end

  def view do
    quote do
      use Phoenix.View,
        root: "lib/boruta_web/templates",
        namespace: Boruta.Support.WebModule

      # Import convenience functions from controllers
      import Phoenix.Controller, only: [get_flash: 1, get_flash: 2, view_module: 1]
    end
  end

  @doc """
  When used, dispatch to the appropriate controller/view/etc.
  """
  defmacro __using__(which) when is_atom(which) do
    apply(__MODULE__, which, [])
  end
end
