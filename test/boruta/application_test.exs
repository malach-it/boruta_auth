defmodule Boruta.ApplicationTest do
  use ExUnit.Case, async: false

  defmodule OtherCache do
    def get(_key), do: {:ok, nil}
    def put(_key, _value, _opts \\ []), do: :ok
    def delete(_key), do: :ok
  end

  test "starts Boruta.Cache when it is the configured cache backend" do
    assert is_pid(Process.whereis(Boruta.Cache))
  end

  test "does not start Boruta.Cache when another cache backend is configured" do
    config = Application.get_env(:boruta, Boruta.Oauth)

    on_exit(fn ->
      Application.put_env(:boruta, Boruta.Oauth, config)
      restart_boruta()
    end)

    Application.put_env(:boruta, Boruta.Oauth, Keyword.put(config, :cache_backend, OtherCache))
    restart_boruta()

    assert is_pid(Process.whereis(Boruta.Supervisor))
    assert Process.whereis(Boruta.Cache) == nil
  end

  defp restart_boruta do
    :ok = Application.stop(:boruta)
    {:ok, _apps} = Application.ensure_all_started(:boruta)
  end
end
