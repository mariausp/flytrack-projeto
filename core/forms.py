# core/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model, password_validation
from datetime import date
import re

from .models import Profile  # se quiser criar o perfil automaticamente

User = get_user_model()  # usa o modelo customizado (core.User)


# --- Formulário de Contato ---
class ContactForm(forms.Form):
    nome = forms.CharField(label="Nome", max_length=80)
    email = forms.EmailField(label="Seu e-mail")
    assunto = forms.CharField(label="Assunto", max_length=120)
    mensagem = forms.CharField(
        label="Mensagem",
        widget=forms.Textarea,
        max_length=4000
    )
    concordo = forms.BooleanField(
        label="Autorizo o contato por e-mail",
        required=True
    )


# --- Função de validação de CPF ---
def validar_cpf(cpf: str) -> bool:
    cpf = re.sub(r'\D', '', cpf or '')
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    def dv(cpf_parcial):
        soma = sum(int(d) * w for d, w in zip(cpf_parcial, range(len(cpf_parcial) + 1, 1, -1)))
        resto = (soma * 10) % 11
        return 0 if resto == 10 else resto

    return dv(cpf[:9]) == int(cpf[9]) and dv(cpf[:10]) == int(cpf[10])


# --- Formulário de Cadastro ---
class SignupForm(UserCreationForm):
    email = forms.EmailField(label="E-mail", required=True)
    birth_date = forms.DateField(
        label="Data de nascimento",
        required=True,
        widget=forms.DateInput(attrs={"type": "date"})
    )
    cpf = forms.CharField(
        label="CPF",
        required=True,
        max_length=11,
        min_length=11,
        help_text="Somente números, 11 dígitos.",
        widget=forms.TextInput(attrs={"inputmode": "numeric"})
    )

    class Meta:
        model = User  # usa core.User automaticamente
        fields = ("username", "email", "birth_date", "cpf", "password1", "password2")

    # --- Validações extras ---
    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Já existe um usuário com este e-mail.")
        return email

    def clean_cpf(self):
        cpf = self.cleaned_data.get("cpf", "")
        cpf_digits = re.sub(r"\D", "", cpf)
        if not validar_cpf(cpf_digits):
            raise forms.ValidationError("CPF inválido.")
        return cpf_digits

    def clean_birth_date(self):
        bd = self.cleaned_data.get("birth_date")
        if bd and bd > date.today():
            raise forms.ValidationError("Data de nascimento inválida.")
        return bd

    # --- Salvamento ---
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        user.cpf = self.cleaned_data["cpf"]
        user.birth_date = self.cleaned_data["birth_date"]

        if commit:
            user.save()
            # mantém Profile em sincronia sem campos inexistentes
            Profile.objects.update_or_create(
                user=user,
                defaults={},
            )
        return user

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label="E-mail", widget=forms.EmailInput(attrs={"autocomplete": "email"}))

    def clean_email(self):
        return self.cleaned_data["email"].strip().lower()  # normaliza

class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(
        label="Nova senha",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )
    new_password_confirm = forms.CharField(
        label="Confirme a nova senha",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        strip=False,
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("new_password")
        p2 = cleaned.get("new_password_confirm")
        if p1 and p2 and p1 != p2:
            self.add_error("new_password_confirm", "As senhas não coincidem.")
        if p1:
            password_validation.validate_password(p1)
        return cleaned
class VooAdminForm(forms.ModelForm):
    class Meta:
        model = Voo  
        fields = ['codigo', 'origem', 'destino', 'partida', 'chegada', 'preco']
        
        widgets = {
            'origem': forms.Select(choices=CIDADES, attrs={'class': 'form-select'}),
            'destino': forms.Select(choices=CIDADES, attrs={'class': 'form-select'}),
            'partida': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'chegada': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'codigo': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ex: GOL-1234'}),
            'preco': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
        }
