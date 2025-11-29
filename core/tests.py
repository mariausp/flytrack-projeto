from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase


class BuscaVoosAPITests(APITestCase):
	def setUp(self):
		self.url = reverse("core:api_busca_voos")
		User = get_user_model()
		self.user = User.objects.create_user(
			username="tester",
			email="tester@example.com",
			password="SenhaSegura123",
		)

	def test_authentication_is_mandatory(self):
		response = self.client.get(self.url)
		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_post_returns_expected_quote(self):
		self.client.force_authenticate(self.user)
		payload = {
			"origem": "São Paulo, SP - BR",
			"destino": "New York, NY - USA",
			"data": "2025-12-18",
			"pax": 2,
		}
		response = self.client.post(self.url, payload, format="json")

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertTrue(response.data["ok"])
		self.assertEqual(response.data["recomendado"]["preco"], 10640)
		self.assertEqual(response.data["parametros"]["pax"], 2)
		self.assertEqual(response.data["parametros"]["data"], "2025-12-18")

	def test_get_works_with_query_params(self):
		self.client.force_authenticate(self.user)
		response = self.client.get(
			self.url,
			{
				"origem": "Brasilia, DF",
				"destino": "Nova Iorque",
			},
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIn("recomendado", response.data)
		self.assertEqual(response.data["parametros"]["origem"], "Brasilia, DF")
