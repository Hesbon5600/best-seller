import json

from rest_framework.renderers import JSONRenderer


class UserJSONRenderer(JSONRenderer):
    charset = 'utf-8'

    def render(self, data, media_type=None, renderer_context=None):
        # If the view throws an error (such as the user can't be authenticated
        # or something similar), `data` will contain an `errors` key. We want
        # the default JSONRenderer to handle rendering errors, so we need to
        # check for this case.
        if data.get('error', ''):
            # As mentioned about, we will let the default JSONRenderer handle
            # rendering errors.
            return super(UserJSONRenderer, self).render(data)
        if data.get('detail', ''):
            data['error'] = data['detail']
            del data['detail']
            return super(UserJSONRenderer, self).render(data)
        # Finally, we can render our data under the "user" namespace.
        token = data['token'][0]
        exp = data['token'][1]
        del data['token']
        return json.dumps(
            {
                "customer": data,
                "accessToken": token,
                "expiresIn": exp
            })
