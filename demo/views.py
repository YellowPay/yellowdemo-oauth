import urllib
from django.shortcuts import render, redirect, render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

import requests
import json
import hmac
import time
import base64
import hashlib
import os
from decimal import Decimal

@require_GET
def home(request):
    ''' Simple view that just displays a "Connect your Yellow account" button.
        This button will redirect the user to a Yellow hosted page to
        grant access to this application.
        
        You'll want something similar. You should redirect to:
        https://api.yellowpay.co/o/authorize/?state=random_state_string&response_type=code&client_id=YOUR_CLIENT_ID
    '''
    error = request.GET.get("error", "")
    yellow_server = "https://{yellow_server}".format(yellow_server=os.environ["YELLOW_SERVER"])
    authorize_url = "{yellow_server}/o/authorize/".format(yellow_server=yellow_server)
    client_id = os.environ["CLIENT_ID"]
    context = { 'authorize_url' : authorize_url,
                'client_id' : urllib.quote(client_id) ,
                'error' : error }
    return render_to_response('demo/home.html', context)

@require_GET
def invoice(request):
    ''' When you registered your application you provided a 'redirect_uri'
        This is the URI that the user will get redirected back to after
        authorizing your application. The redirection will include a
        'code' query argument which is set with an authorization code
        you'll use to request an access token (and refresh token) from Yellow.
        
        You'll (finally) be able to use this access token to create invoices
        on behalf of the user. Periodically the access token will expire
        when this happens you should use the refresh token to request a
        new access token (you can refresh the access token earlier if you'd
        like)
        
        Both access token and refresh token should be stored securely on your
        server.'''
        
    yellow_server = "https://{yellow_server}".format(yellow_server=os.environ["YELLOW_SERVER"])
    
    # -------------------------------------------------------------------------
    # Request access token
    # -------------------------------------------------------------------------
    authorization_code = request.GET.get("code", None)
    access_token, refresh_token = request_access_token(yellow_server,
                                                       authorization_code)
    
    # -------------------------------------------------------------------------
    # Create invoice
    # -------------------------------------------------------------------------
    return create_invoice(yellow_server, access_token, refresh_token)


def request_access_token(yellow_server, 
                         authorization_code):
    ''' Authorization code is sent from  Yellow and used to request an access
        token. Note that it would be trivial for a hacker to send a false
        Authorization Code (e.g., by making a GET request to /invoice/ and
        provide a 'code' query arg)- but it wouldn't accomplish much since you
        will always have to request the Access Token directly from the
        YELLOW_SERVER (Which will reject the request if given a bad Code)
    '''
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]
    access_url = "{yellow_server}/o/token/".format(yellow_server=yellow_server)
    
    # Access token is requested via POST with the following payload:
    body = { "grant_type" : "authorization_code",
             "code" : authorization_code,
             "redirect_uri" : "{root_url}/invoice/".format(root_url=os.environ["ROOT_URL"]),
             "client_id" : client_id }
    # OAuth2 uses basic authentication so it's extra important that any
    # communication with the Yellow server happens over SSL. You'll see above
    # that 'yellow_server' and 'access_url' are forced to HTTPS.
    r = requests.post(access_url,
                      auth=requests.auth.HTTPBasicAuth(client_id, client_secret),
                      data=body,
                      verify=True)
    data = r.json()
    
    return data['access_token'],  data['refresh_token']

def refresh_access_token(yellow_server, refresh_token):
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]
    access_url = "{yellow_server}/o/token/".format(yellow_server=yellow_server)

    # Access token may have expired, try to refresh
    body = { "grant_type" : "refresh_token",
             "refresh_token" : refresh_token }
    # OAuth2 uses basic authentication so it's extra important that any
    # communication with the Yellow server happens over SSL. You'll see above
    # that 'yellow_server' and 'access_url' are forced to HTTPS.
    r = requests.post(access_url,
                      auth=requests.auth.HTTPBasicAuth(client_id, client_secret),
                      data=body,
                      verify=True)
    data = r.json()
    
    return data['access_token'], data['refresh_token']
        
def create_invoice(yellow_server,
                   access_token,
                   refresh_token):
    # -------------------------------------------------------------------------
    # Create invoice
    # -------------------------------------------------------------------------
    invoice_url = "{yellow_server}/api/invoice/".format(yellow_server=yellow_server)
    # POST /api/invoice/ expects a base price, currency, and optional callback. 
    # ROOT_URL should refer to a server you control
    payload= { 'base_price' : "0.30", 
               'base_ccy' : "USD",
               'callback' : "{host}/ipn/".format(host=os.environ["ROOT_URL"])}
          
    body = json.dumps(payload)
      
    # 'Bearer' authentication using the access token as credentials
    headers = {'content-type': 'application/json',
               'Authorization': "Bearer %s" % access_token}
    
    # POST the request
    r = requests.post(invoice_url,
                      data=body,
                      headers=headers,
                      verify=True)
    if 200 == r.status_code:
        # At this point the demo just redirects to the invoice widget. A
        # non-demo site might instead embed the invoice in a shopping cart and
        # also open a order in an Order Management System and attach the
        # returned invoice id.
        data = r.json()
        return redirect(data['url'])
    elif 403 == r.status_code:
        access_token, refresh_token = refresh_access_token(yellow_server, refresh_token)
        return create_invoice(yellow_server, access_token, refresh_token)
    else:
        return redirect("/?error=%s" % r.text)

def get_signature(url, body, nonce):
    ''' To secure communication from Yellow server to your server we
        use a form of HMAC authentication.
        (http://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
         
        When submitting a request 3 additional header elements are included:
        API-Key: your public Client ID, you received this when registering
                 your application
        API-Nonce: an ever-increasing number that is different for each request
                   (e.g., current UNIX time in milliseconds)
        API-Sign: an HMAC hash signed with your Client secret and converted to
                  hexadecimal. The message to be hahed and signed is the
                  concatenation of the nonce, fully-qualified request URL,
                  and any request parameters.
                        
        This allows you to authenticate the request as coming from us,
        prevents anyone else from modifying or replaying the request, and
        ensures your secret key is never exposed (even in a Heartbleed-type
        scenario where the SSL layer itself is compromised).
        '''
     
    # When an invoice has been created by an 'application' (i.e. OAuth
    # consumer or client) the application's client secret is used to sign
    # the IPN (as opposed to the Merchant's API secret which is used to sign
    # IPNs for invoices that the merchant has created themselves without the
    # use of a 3rd party application)
    secret = os.environ.get("CLIENT_SECRET", "")
     
    # Concatenate the components of the request to be hashed. They should
    # always be concatenated in this order: Nonce, fully-qualified URL
    # (e.g. https://yellowpay.co/api/invoice/), body
    message = str(nonce) + url + body
     
    # Hash and sign the message with your API secret
    h = hmac.new(secret,
                 message,
                 hashlib.sha256)
     
    # Convert he signature to hexadecimal
    signature = h.hexdigest()
     
    return signature
 
 
@csrf_exempt # No CSRF token is needed or expected
def ipn(request):
    ''' Entry point for the IPN callback. An example approach would be to:
        1. Grab the invoice id and status from the POST payload
        2. Query the order management system for an order matching the invoice
        3a. If the status is 'unconfirmed' flag the order as
            'pending confirmation' and redirect the customer to an order
            complete page
        3b. If the status is 'paid' flag th order as 'complete' and ship the
            the product
    '''
 
    # Yellow signs its requests with same mechanism clients sign their
    # requests to Yellow API. Therefore, the same logic can be used to verify
    # the signature.
    signature = request.META['HTTP_API_SIGN']
 
    # Nonces, as is described above, is useful against replay attacks. To 
    # implement nonce checks, the merchant application has to store the last
    # nonce received from Yellow and make sure that this nonce is a fresh one
    # with a higher value than the old one.
    #
    # Because this is just a demo application with no database, we're not
    # implementing the nonce checking. Furthermore, the current set of 
    # functionality that is enabled by IPN requests make replay attacks
    # of little value anyway.
    nonce = request.META['HTTP_API_NONCE']
    body = request.body
 
    # the URL in this case is the merchant IPN URL registered with
    # Yellow when the invoice was created
    url = "{host}/ipn/".format(host=os.environ["ROOT_URL"])
 
    test_signature = get_signature(url, body, nonce)
 
    if test_signature != signature:
        # If signatures are not the same, that means it could be a malicious request:
        # reject it.
        return HttpResponse(status=403)
         
 
    payload = json.loads(request.body)
    invoice = payload.get("id", None)
    status = payload.get("status", None)
    if (None == invoice or None == status):
        # This should never happen (we'll always include an invoice id and
        # status), but if it does responding with a 400 will alert us to a
        # problem.
        return HttpResponse(status=400)
     
    print "Querying Order Management System for order matching invoice id %s" % invoice
     
    if 'authorizing' == status:
        print "Order is 'pending confirmation', redirecting customer to order complete page."
    elif 'paid' == status:
        print "Order is 'complete', shipping product to customer."
 
    return HttpResponse()


