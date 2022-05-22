defmodule Boruta.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  it cannot be async. For this reason, every test runs
  inside a transaction which is reset at the beginning
  of the test unless the test case is marked as async.
  """

  use ExUnit.CaseTemplate

  alias Boruta.Ecto.Scopes
  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      alias Boruta.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Boruta.DataCase
    end
  end

  setup tags do
    :ok = Sandbox.checkout(Boruta.Repo)
    :ok = Scopes.invalidate(:public)

    unless tags[:async] do
      Sandbox.mode(Boruta.Repo, {:shared, self()})
    end

    :ok
  end
end
