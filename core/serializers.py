from rest_framework import serializers


class FlightSearchSerializer(serializers.Serializer):
	origem = serializers.CharField(max_length=120, required=False, allow_blank=True, default="")
	destino = serializers.CharField(max_length=120, required=False, allow_blank=True, default="")
	data = serializers.DateField(required=False, allow_null=True, input_formats=["%Y-%m-%d"])  # ISO (YYYY-MM-DD)
	pax = serializers.IntegerField(required=False, min_value=1, max_value=9, default=1)

	def validate(self, attrs):
		# Default to 1 pax even if blank/None sneaks through request
		attrs["pax"] = attrs.get("pax") or 1
		return attrs


class FlightPriceSerializer(serializers.Serializer):
	preco = serializers.IntegerField(min_value=0)
	preco_fmt = serializers.CharField(max_length=32)
	descricao = serializers.CharField(allow_blank=True, required=False, default="")


class FlightSearchParamsSerializer(serializers.Serializer):
	origem = serializers.CharField(allow_blank=True, default="")
	destino = serializers.CharField(allow_blank=True, default="")
	data = serializers.CharField(allow_blank=True, default="")
	pax = serializers.IntegerField(min_value=1, default=1)


class FlightSearchResponseSerializer(serializers.Serializer):
	ok = serializers.BooleanField()
	recomendado = FlightPriceSerializer()
	mais_barato = FlightPriceSerializer()
	parametros = FlightSearchParamsSerializer()
