Yellow Oauth Demo
=================

Demo code for requesting an OAuth access token and using it to create an
invoice on behalf of a merchant.

This is a simple Django server that will walk through the following
authorization flow:

1. Merchant clicks "Connect your Yellow account"
2. Merchant is redirected to an OAuth authorization page to grant Invoice creation authority to a 3rd party application
3. After authority is granted, Merchant is redirected to the application provided redirect URI including an authorization code in the GET parameters (in the case of this demo that is assumed to be "/invoice/" on the local server)
4. Application uses the Authorization Code to request an Acccess Token
5. Access Token is granted and application uses it to create an invoice on behalf of the merchant

A live version of this app is running at: https://yellow-demo-oauth.herokuapp.com

*views.py* contains sample code and additional documentation. For any other questions please email info@yellowpay.co

Thanks for using Yellow!

