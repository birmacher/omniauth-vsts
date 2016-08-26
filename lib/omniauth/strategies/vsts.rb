require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class VSTS < OmniAuth::Strategies::OAuth2
      option :name, 'vsts'
      option :authorize_params, {:response_type => 'Assertion'}
      option :token_params, {
        :client_assertion_type => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        :client_assertion => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im9PdmN6NU1fN3AtSGpJS2xGWHo5M3VfVjBabyJ9.eyJjaWQiOiJjZmI4N2U1MS00NGJlLTRlZjEtOWUxNC02OTVlZGZjODFiOTciLCJjc2kiOiIyYzUyMDU2My0zMjhiLTQzMGMtOGUzNy0wN2NhODg2ZjgxOWEiLCJuYW1laWQiOiIyNzk2ZjU2Ni03OWUzLTQ3YmItOTU5Ny1kMzFlYmM5MDU3ZDMiLCJpc3MiOiJhcHAudnNzcHMudmlzdWFsc3R1ZGlvLmNvbSIsImF1ZCI6ImFwcC52c3Nwcy52aXN1YWxzdHVkaW8uY29tIiwibmJmIjoxNDcyMTI4NzEzLCJleHAiOjE2Mjk4OTUxMTN9.dMBpndiMeePFCkZeszncx0_kTjxv5PhhLGwklUZ4Wngtg9v7D30YfRyVERlPfYs76ZC4hgXlmd47Aaw3ZefvIoK6cGfyacpBoQf2df_Ac9qoAgEPyUw_WvgmeBmdsGlJ0Ubs-OOz9-AgESGiuCAABNk1oCDM8AlPlMYprL2Dcz7M0bzS1yIgTYc06YJqJGDoEqkL7Zbgx2wKOb9tMQ92bUq433KhxPW8t43A0dai2jm0XSRzWyxHgiCfyJ9q-J0GHXsNATTuzGAbt8ArkWSQrx7rCIBdKprWpkO8NCpPHp0pJLeAnKxk-ahp4RnuJhLkRU3RKfQBrvHSZl-3Rlis3Q',
        :grant_type => 'urn:ietf:params:oauth:grant-type:jwt-bearer'
      }

      option :client_options, {
        :site => 'https://app.vssps.visualstudio.com',
        :authorize_url => '/oauth2/authorize',
        :token_url =>  '/oauth2/token'
      }

      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        super.tap do |params|
          %w[client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      uid { raw_info['id'].to_s }
      
      info do
        {
          'name' => raw_info['displayName'],
          'email' => raw_info['emailAddress'],
          'public_alias' => raw_info['publicAlias']
        }
      end

      extra do
        {:raw_info => raw_info }
      end

      def raw_info
        @raw_info ||= access_token.get('/_apis/profile/profiles/me?api-version=1.0').parsed
      end

      protected

      def build_access_token
        assertion = request.params["code"]
        client.get_token({:assertion => assertion, :redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)))
      end
    end
  end
end

OmniAuth.config.add_camelization 'vsts', 'VSTS'
