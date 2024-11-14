defmodule Boruta.TokenGenerator do
  @moduledoc false

  @behaviour Boruta.Oauth.TokenGenerator

  use Puid, bits: 512, charset: :alphanum

  defmodule TxCode do
    @moduledoc false

    use Puid, charset: :decimal, bits: 13
  end

  @impl Boruta.Oauth.TokenGenerator
  def tx_code_length do
    4
  end

  @impl Boruta.Oauth.TokenGenerator
  def tx_code_input_mode do
    "numeric"
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
