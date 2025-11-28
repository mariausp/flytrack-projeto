from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_portalmeta_remove_profile_birth_date_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="ticket",
            name="assentos",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
    ]
