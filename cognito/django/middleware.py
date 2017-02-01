from django.utils.deprecation import MiddlewareMixin


class TokenBasedAuthMiddleware(MiddlewareMixin):

    def process_request(self, request):
        pass
