
class APIKeyMiddleware(object):
    """
        A simple middleware to pull the users API key from the headers and
        attach it to the request.

        It should be compatible with both old and new style middleware.
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        self.process_request(request)
        response = self.get_response(request)

        return response

    @staticmethod
    def process_request(request):
        if 'HTTP_AUTHORIZATION_ID' in request.META:
            request.api_key = request.META['HTTP_AUTHORIZATION_ID']

        return None
