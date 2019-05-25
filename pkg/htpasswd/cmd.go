package htpasswd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd/api"
)

// CommandOptions ...
type CommandOptions struct {
	configFlags *genericclioptions.ConfigFlags
	context     *api.Context
	clientset   *kubernetes.Clientset
	rawConfig   api.Config

	args         []string
	namespace    string
	secretName   string
	username     string
	keyName      string
	createSecret bool
	deleteUser   bool
	listUsers    bool

	genericclioptions.IOStreams
}

// NewCommand ...
func NewCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := CommandOptions{
		configFlags: genericclioptions.NewConfigFlags(true),

		IOStreams: streams,
	}

	cmd := &cobra.Command{
		Use:   "htpasswd SECRET <username>",
		Short: "Create or edit a htpasswd secret",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(c, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Run(); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&o.createSecret, "create", "c", false, "Create a new secret")
	cmd.Flags().BoolVarP(&o.deleteUser, "delete-user", "D", false, "Delete the specified user")
	cmd.Flags().BoolVarP(&o.listUsers, "list-users", "l", false, "List users")
	cmd.Flags().StringVarP(&o.keyName, "key-name", "", "auth", "Secret key name")
	o.configFlags.AddFlags(cmd.Flags())

	return cmd
}

// Complete populates some fields from the factory, grabs command line
// arguments and looks up the node using Builder
func (o *CommandOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	var err error
	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	context, exists := o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	if !exists {
		return fmt.Errorf("missing context")
	}
	o.context = context
	if o.configFlags.Namespace != nil && *o.configFlags.Namespace != "" {
		o.namespace = *o.configFlags.Namespace
	} else {
		o.namespace = context.Namespace
	}

	config, err := o.configFlags.ToRESTConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	o.clientset = clientset

	return nil
}

// Validate validates commandline arguments.
func (o *CommandOptions) Validate() error {
	if len(o.args) == 1 && o.listUsers {
		o.secretName = o.args[0]
		return nil
	} else if len(o.args) == 2 {
		o.secretName = o.args[0]
		o.username = o.args[1]
		return nil
	}
	return fmt.Errorf("secret and username are required")
}

// Run runs the htpasswd command.
func (o *CommandOptions) Run() error {
	var err error
	secret, data, err := o.getSecret()
	if err != nil {
		return err
	}

	htpasswd, err := newPasswordFile(data)
	if err != nil {
		return err
	}

	if o.listUsers {
		users, err := htpasswd.ListUsers()
		if err != nil {
			return err
		}
		fmt.Printf("Existing users:\n")
		for _, u := range users {
			fmt.Println(u)
		}
		return nil
	}

	if o.deleteUser {
		if err := htpasswd.DeleteUser(o.username); err != nil {
			return err
		}
		secret.Data[o.keyName] = htpasswd.Bytes()
		_, err = o.clientset.CoreV1().Secrets(o.namespace).Update(secret)
		return err
	}

	fmt.Printf("Enter password: ")
	password1, err := terminal.ReadPassword(0)
	if err != nil {
		return err
	}
	fmt.Printf("\nRepeat password: ")
	password2, err := terminal.ReadPassword(0)
	if err != nil {
		return err
	}
	fmt.Printf("\n")
	if string(password1) != string(password2) {
		fmt.Println("passwords don't match")
		os.Exit(1)
	}

	if err := htpasswd.SetPassword(o.username, string(password1)); err != nil {
		return err
	}
	secret.Data[o.keyName] = htpasswd.Bytes()
	if o.createSecret {
		_, err = o.clientset.CoreV1().Secrets(o.namespace).Create(secret)
	} else {
		_, err = o.clientset.CoreV1().Secrets(o.namespace).Update(secret)
	}
	if err != nil {
		fmt.Println("Password updated successfully")
	}
	return err
}

func (o *CommandOptions) getSecret() (*v1.Secret, []byte, error) {
	if o.createSecret {
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      o.secretName,
				Namespace: o.namespace,
			},
			Type: v1.SecretTypeOpaque,
			Data: make(map[string][]byte),
		}
		return secret, nil, nil
	}

	secret, err := o.clientset.CoreV1().Secrets(o.namespace).Get(o.secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		fmt.Printf("Secret %q not found\n", o.secretName)
		os.Exit(1)
	} else if statusError, isStatus := err.(*apierrors.StatusError); isStatus {
		fmt.Printf("Error getting secret %v\n", statusError.ErrStatus.Message)
		os.Exit(1)
	} else if err != nil {
		fmt.Printf("Unkown error: %v", err)
		os.Exit(1)
	}

	if secret.Type != v1.SecretTypeOpaque {
		return nil, nil, fmt.Errorf("invalid secret type")
	}
	data, exists := secret.Data[o.keyName]
	if !exists {
		return nil, nil, fmt.Errorf("Secret with key %q does not exist", o.keyName)
	}
	return secret, data, nil
}
