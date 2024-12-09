defmodule Boruta.TokenGenerator do
  @moduledoc false

  @behaviour Boruta.Oauth.TokenGenerator

  use Puid, bits: 512, charset: :alphanum

  defmodule TxCode do
    @moduledoc false

    use Puid, charset: :alpha_upper, bits: 16
  end

  @impl Boruta.Oauth.TokenGenerator
  def generate(:tx_code, _) do
    TxCode.generate()
  end

  def generate(_, _) do
    generate()
  end

  @impl Boruta.Oauth.TokenGenerator
  def secret(_) do
    generate()
  end
end
