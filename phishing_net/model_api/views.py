from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import SMSSerializer
from .models import MSGS
from .attributes import SpamText, features_result
from urlextract import URLExtract
import pickle
import xgboost as xgb


def get_url_classification(url, url_c):
    model = xgb.XGBRegressor()
    model.load_model("phishxgb.bin")
    is_not_spam = {1: True, 0: False}
    green_c, red_c = 0, 0
    for i in range(url_c):
        try:
            features = [features_result(url[i])]
            if is_not_spam[round(model.predict(features)[0])]:
                green_c += 1
            else:
                red_c += 1
        except:
             red_c += 1
    return (green_c / (red_c + green_c)   >= 0.70)
    


@api_view(['GET'])
def api_connect(request):
    context = {'prediction' : 1, 'confidence' : 77}
    return Response(context)
    #return HttpResponse("<html> <h1> Hi </html>")

@api_view(['GET'])
def get_messages(request):
    sms = MSGS.objects.all()
    serializer = SMSSerializer(sms, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def get_message(request, key):
    sms = MSGS.objects.get(id=key)
    serializer = SMSSerializer(sms, many=False)
    return Response(serializer.data)


@api_view(['POST'])
def create_sms(request):
    data = request.data
    print(data)
    #msg = "Hi win cash by clicking {url}. Hurry!"
    # model1 (features(url))
    # model2 (msg content)
    extractor = URLExtract()
    #if else green or red
    url = extractor.find_urls(data['body'])
    url_c = len(url)
    flag_val = True
    text_list = data['body'].split()
    if url_c >= 1:
        print("here")
        flag_val = get_url_classification(url, url_c)
        print("there", url, flag_val)
        text = " ".join(text_list)
        for x in url:
            text = text.replace(x, '')
    else:
        text = data['body']
    if text != "":
        spammer = SpamText()
        txt = spammer.is_not_text_spam(text)
        model1 = pickle.load(open('textspam.sav', 'rb'))
        text_is_not_spam = (model1.predict([txt]) > 0)
    else:
        text_is_not_spam = True

    if flag_val and text_is_not_spam:
        flag_col = 'green'
    elif not text_is_not_spam and flag_val:
        flag_col = 'yellow'
    else:
        flag_col = 'red'

    sms = MSGS.objects.create(
        body=data['body'],
        address=data['address'],
        flag=flag_col
    )
    serializer = SMSSerializer(sms, many=False)
    return Response(serializer.data)


@api_view(['DELETE'])
def delete_sms(request, key):
    sms = MSGS.objects.get(id=key)
    sms.delete()
    return Response("Message Deleted Successfully")

